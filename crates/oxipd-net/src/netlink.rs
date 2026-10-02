//! Thin async wrapper around the `rtnetlink` crate: link lookup/up-down,
//! address add/del/dump, route add/del, and a merged multicast event
//! stream (link/address/route/neighbour changes) — the async analogue of
//! dhcpcd's `if-linux.c` netlink layer, minus the manual TLV building since
//! `rtnetlink`/`netlink-packet-route` already provide that.
//!
//! One [`NetlinkClient`] is backed by a single netlink socket used for both
//! outgoing requests and the unsolicited multicast stream: `netlink_proto`
//! (which `rtnetlink` is built on) already demultiplexes sequence-matched
//! replies from unsolicited/multicast traffic on the same socket, so there
//! is no need for dhcpcd's separate "async listener" + "sync request"
//! socket pair.

use std::net::IpAddr;

use futures::{StreamExt, TryStreamExt};
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags, AddressMessage, CacheInfo},
    link::{AfSpecInet6, AfSpecUnspec, In6AddrGenMode, LinkAttribute, LinkFlags, LinkMessage},
    route::RouteMessage,
    AddressFamily, RouteNetlinkMessage,
};
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::{new_multicast_connection, Handle, LinkUnspec, MulticastGroup};

pub use netlink_packet_route::route::{RouteAttribute, RouteProtocol, RouteScope, RouteType};
pub use rtnetlink::RouteMessageBuilder;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("netlink request failed: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("failed to open netlink socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("interface not found: {0}")]
    LinkNotFound(String),
    #[error("address not found on interface {ifindex}: {address}/{prefix_len}")]
    AddressNotFound {
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    },
}

/// The subset of `RTM_NEWLINK`/`RTM_GETLINK` fields oxipd-core needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub index: u32,
    pub name: String,
    pub mtu: Option<u32>,
    pub hwaddr: Vec<u8>,
    pub is_up: bool,
    pub has_carrier: bool,
}

fn link_info_from_message(msg: LinkMessage) -> LinkInfo {
    let index = msg.header.index;
    let is_up = msg.header.flags.contains(LinkFlags::Up);
    let has_carrier = msg.header.flags.contains(LinkFlags::Running);
    let mut name = String::new();
    let mut mtu = None;
    let mut hwaddr = Vec::new();
    for attr in msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = n,
            LinkAttribute::Mtu(m) => mtu = Some(m),
            LinkAttribute::Address(a) => hwaddr = a,
            _ => {}
        }
    }
    LinkInfo {
        index,
        name,
        mtu,
        hwaddr,
        is_up,
        has_carrier,
    }
}

/// A change observed on the merged multicast stream. Deliberately coarse
/// (full new state, not a field-level diff) — callers re-derive whatever
/// they need from `LinkInfo`/addresses, matching how the netlink protocol
/// itself always sends a full object per change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkEvent {
    LinkNew(LinkInfo),
    LinkDel(u32),
    AddrNew {
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    },
    AddrDel {
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    },
    /// The kernel finished IPv6 DAD on this address and found a duplicate
    /// (`IFA_F_DADFAILED`).
    AddrDadFailed {
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    },
    RouteNew,
    RouteDel,
}

fn addr_event(msg: AddressMessage, is_new: bool) -> Option<NetlinkEvent> {
    let ifindex = msg.header.index;
    let prefix_len = msg.header.prefix_len;
    let address = msg.attributes.iter().find_map(|a| match a {
        AddressAttribute::Address(addr) => Some(*addr),
        _ => None,
    })?;
    let dad_failed = msg
        .attributes
        .iter()
        .any(|a| matches!(a, AddressAttribute::Flags(f) if f.contains(AddressFlags::Dadfailed)));
    if is_new && dad_failed {
        return Some(NetlinkEvent::AddrDadFailed {
            ifindex,
            address,
            prefix_len,
        });
    }
    Some(if is_new {
        NetlinkEvent::AddrNew {
            ifindex,
            address,
            prefix_len,
        }
    } else {
        NetlinkEvent::AddrDel {
            ifindex,
            address,
            prefix_len,
        }
    })
}

fn translate(msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<NetlinkEvent> {
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(l)) => {
            Some(NetlinkEvent::LinkNew(link_info_from_message(l)))
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(l)) => {
            Some(NetlinkEvent::LinkDel(l.header.index))
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(a)) => addr_event(a, true),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(a)) => addr_event(a, false),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_)) => {
            Some(NetlinkEvent::RouteNew)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(_)) => {
            Some(NetlinkEvent::RouteDel)
        }
        _ => None,
    }
}

/// The unsolicited-message half of a [`NetlinkClient`].
pub struct NetlinkEvents {
    rx: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        netlink_sys::SocketAddr,
    )>,
}

impl NetlinkEvents {
    /// Wait for the next link/address/route change. Uninteresting message
    /// types (acks, dumps-in-progress, etc.) are skipped internally.
    pub async fn recv(&mut self) -> Option<NetlinkEvent> {
        loop {
            let (msg, _from) = self.rx.next().await?;
            if let Some(ev) = translate(msg) {
                return Some(ev);
            }
        }
    }
}

/// One netlink socket, subscribed to link/address/route/neighbour
/// multicast groups, plus request/reply access via `rtnetlink::Handle`.
#[derive(Clone)]
pub struct NetlinkClient {
    handle: Handle,
}

impl NetlinkClient {
    /// Open the netlink socket, subscribe to the groups oxipd cares about,
    /// and spawn the background task that drives the connection. Returns
    /// the request/reply client plus the separate event-stream handle.
    pub fn spawn() -> Result<(Self, NetlinkEvents), Error> {
        let (conn, handle, messages) = new_multicast_connection(&[
            MulticastGroup::Link,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
            MulticastGroup::Neigh,
        ])?;
        tokio::spawn(conn);
        Ok((NetlinkClient { handle }, NetlinkEvents { rx: messages }))
    }

    pub async fn link_by_name(&self, name: &str) -> Result<LinkInfo, Error> {
        let mut stream = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match stream.try_next().await? {
            Some(msg) => Ok(link_info_from_message(msg)),
            None => Err(Error::LinkNotFound(name.to_string())),
        }
    }

    pub async fn link_by_index(&self, index: u32) -> Result<LinkInfo, Error> {
        let mut stream = self.handle.link().get().match_index(index).execute();
        match stream.try_next().await? {
            Some(msg) => Ok(link_info_from_message(msg)),
            None => Err(Error::LinkNotFound(index.to_string())),
        }
    }

    pub async fn set_link_up(&self, index: u32) -> Result<(), Error> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn set_link_down(&self, index: u32) -> Result<(), Error> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).down().build())
            .execute()
            .await?;
        Ok(())
    }

    /// Set `IFLA_INET6_ADDR_GEN_MODE = NONE`, stopping the kernel from
    /// generating its own link-local/SLAAC addresses on `index` so
    /// `oxipd_core::ipv6nd` can own address generation and DAD timing
    /// itself (matches dhcpcd's `if_disable_autolinklocal`). Combine with
    /// `oxipd_net::sysctl::disable_kernel_autoconf` (which stops the
    /// kernel's own RS/RA handling) for full manual control.
    pub async fn disable_kernel_addr_gen(&self, index: u32) -> Result<(), Error> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.interface_family = AddressFamily::Unspec;
        message
            .attributes
            .push(LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(
                vec![AfSpecInet6::AddrGenMode(In6AddrGenMode::None)],
            )]));
        self.handle.link().set(message).execute().await?;
        Ok(())
    }

    /// Add an address (IPv4 or IPv6) to an interface. Broadcast/local NLAs
    /// for IPv4 are filled in automatically by `rtnetlink`'s builder.
    pub async fn add_addr(&self, index: u32, address: IpAddr, prefix_len: u8) -> Result<(), Error> {
        self.handle
            .address()
            .add(index, address, prefix_len)
            .execute()
            .await?;
        Ok(())
    }

    /// Add an address with an explicit `IFA_CACHEINFO` valid/preferred
    /// lifetime, so the kernel itself enforces SLAAC/DHCP expiry instead
    /// of the address being permanent until oxipd explicitly removes it
    /// (matches dhcpcd's own reliance on kernel-enforced lifetimes).
    pub async fn add_addr_with_lifetime(
        &self,
        index: u32,
        address: IpAddr,
        prefix_len: u8,
        valid_secs: u32,
        preferred_secs: u32,
    ) -> Result<(), Error> {
        let mut request = self
            .handle
            .address()
            .add(index, address, prefix_len)
            .replace();
        let mut cache_info = CacheInfo::default();
        cache_info.ifa_valid = valid_secs;
        cache_info.ifa_preferred = preferred_secs;
        request
            .message_mut()
            .attributes
            .push(AddressAttribute::CacheInfo(cache_info));
        request.execute().await?;
        Ok(())
    }

    /// Remove an address. Requires one dump-and-match round trip since the
    /// kernel's `RTM_DELADDR` needs the exact message the kernel holds
    /// (there is no "delete by value" shortcut over netlink).
    pub async fn del_addr(&self, index: u32, address: IpAddr, prefix_len: u8) -> Result<(), Error> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_address_filter(address)
            .set_prefix_length_filter(prefix_len)
            .execute();
        match stream.try_next().await? {
            Some(msg) => {
                self.handle.address().del(msg).execute().await?;
                Ok(())
            }
            None => Err(Error::AddressNotFound {
                ifindex: index,
                address,
                prefix_len,
            }),
        }
    }

    /// Dump every address currently configured on an interface.
    pub async fn addrs(&self, index: u32) -> Result<Vec<(IpAddr, u8)>, Error> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut out = Vec::new();
        while let Some(msg) = stream.try_next().await? {
            let prefix_len = msg.header.prefix_len;
            if let Some(addr) = msg.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(a) => Some(*a),
                _ => None,
            }) {
                out.push((addr, prefix_len));
            }
        }
        Ok(out)
    }

    /// Add a route. Build `route` with [`RouteMessageBuilder`] (re-exported
    /// from this module) — route shapes vary too much (default route,
    /// on-link subnet route, host route, RFC4191 preference, ...) to wrap
    /// further without just re-inventing `rtnetlink`'s own builder.
    pub async fn add_route(&self, route: RouteMessage) -> Result<(), Error> {
        self.handle.route().add(route).execute().await?;
        Ok(())
    }

    pub async fn del_route(&self, route: RouteMessage) -> Result<(), Error> {
        self.handle.route().del(route).execute().await?;
        Ok(())
    }

    /// Install (or replace) an IPv6 default route via `gateway`, tagged
    /// with the RA route protocol so it's recognisable as ours.
    pub async fn add_default_route_v6(
        &self,
        index: u32,
        gateway: std::net::Ipv6Addr,
    ) -> Result<(), Error> {
        let route = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(std::net::Ipv6Addr::UNSPECIFIED, 0)
            .gateway(gateway)
            .output_interface(index)
            .protocol(RouteProtocol::Ra)
            .build();
        self.handle.route().add(route).replace().execute().await?;
        Ok(())
    }

    pub async fn del_default_route_v6(
        &self,
        index: u32,
        gateway: std::net::Ipv6Addr,
    ) -> Result<(), Error> {
        let route = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(std::net::Ipv6Addr::UNSPECIFIED, 0)
            .gateway(gateway)
            .output_interface(index)
            .protocol(RouteProtocol::Ra)
            .build();
        self.handle.route().del(route).execute().await?;
        Ok(())
    }

    /// Dump every IPv4 or IPv6 route currently in the kernel's main table.
    pub async fn routes(&self, family: rtnetlink::IpVersion) -> Result<Vec<RouteMessage>, Error> {
        let route = match family {
            rtnetlink::IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
            rtnetlink::IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
        };
        let mut stream = self.handle.route().get(route).execute();
        let mut out = Vec::new();
        while let Some(msg) = stream.try_next().await? {
            out.push(msg);
        }
        Ok(out)
    }
}
