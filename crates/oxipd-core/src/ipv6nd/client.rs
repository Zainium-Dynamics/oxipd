//! The async shell driving [`RouterList`] over a real ICMPv6 socket and
//! netlink — the RS/RA analogue of `dhcp4::client::Dhcp4Client`. Not unit
//! tested (needs a real raw socket, `CAP_NET_RAW`, and a real router on
//! the network); exercised manually instead (see the module docs on
//! PLAN.md's M4 milestone verification step).
//!
//! DHCPv6 itself is not implemented yet: [`RaEvent::Dhcp6`] triggers are
//! only logged for now, not acted on.

use std::net::IpAddr;
use std::time::Duration;

use oxipd_net::icmp6::{RawIcmp6Socket, ALL_ROUTERS_MULTICAST};
use oxipd_net::netlink::{NetlinkClient, NetlinkEvent, NetlinkEvents};
use oxipd_net::sysctl;
use oxipd_proto::ndp::{self, PrefixInformation, RouterAdvertisement};
use tokio::time::Instant;

use super::{RaEvent, RouterList};
use crate::ipv6::slaac;

/// RFC 4861 §10 constants for Router Solicitation retransmission.
pub const MAX_RTR_SOLICITATION_DELAY: Duration = Duration::from_secs(1);
pub const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
pub const MAX_RTR_SOLICITATIONS: u32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Socket(#[from] oxipd_net::icmp6::Error),
    #[error(transparent)]
    Netlink(#[from] oxipd_net::netlink::Error),
}

/// Which scheme to use for SLAAC interface identifiers on this interface.
pub enum IidScheme {
    Eui64 { mac: [u8; 6] },
    Rfc7217 { net_iface: Vec<u8>, secret: Vec<u8> },
}

impl IidScheme {
    /// EUI-64 ignores `dad_counter`, so a DAD failure there has no
    /// alternative address; RFC 7217 gets a fresh one per counter value.
    fn make_iid(&self, pio: &PrefixInformation, dad_counter: u8) -> slaac::Iid {
        match self {
            IidScheme::Eui64 { mac } => slaac::eui64_iid(*mac),
            IidScheme::Rfc7217 { net_iface, secret } => {
                slaac::rfc7217_iid(pio.prefix, net_iface, &[], dad_counter, secret)
            }
        }
    }
}

pub struct Ipv6NdClient {
    socket: RawIcmp6Socket,
    ifname: String,
    ifindex: u32,
    iid_scheme: IidScheme,
    router_list: RouterList,
    netlink: NetlinkClient,
    events: NetlinkEvents,
}

impl Ipv6NdClient {
    /// Hand kernel RS/RA/SLAAC control over to oxipd (`sysctl::
    /// disable_kernel_autoconf` + `netlink::disable_kernel_addr_gen`) and
    /// build a client ready to run.
    pub async fn new(
        ifname: String,
        ifindex: u32,
        socket: RawIcmp6Socket,
        iid_scheme: IidScheme,
        netlink: NetlinkClient,
        events: NetlinkEvents,
        temporary_addresses: bool,
    ) -> Result<Self, Error> {
        sysctl::disable_kernel_autoconf(&ifname).await?;
        netlink.disable_kernel_addr_gen(ifindex).await?;
        Ok(Ipv6NdClient {
            socket,
            ifname,
            ifindex,
            iid_scheme,
            router_list: RouterList::new().with_temporary_addresses(temporary_addresses),
            netlink,
            events,
        })
    }

    pub fn router_list(&self) -> &RouterList {
        &self.router_list
    }

    /// Solicit and process Router Advertisements until the netlink event
    /// stream closes. Sends up to
    /// [`MAX_RTR_SOLICITATIONS`] Router Solicitations (stopping early once
    /// any RA is received) and periodically sweeps for expired prefixes.
    pub async fn run(&mut self) -> Result<(), Error> {
        tokio::time::sleep(MAX_RTR_SOLICITATION_DELAY).await;
        self.send_rs().await?;
        let mut solicitations_sent = 1u32;

        let mut buf = vec![0u8; 1500];
        loop {
            let rs_deadline = (solicitations_sent < MAX_RTR_SOLICITATIONS)
                .then(|| Instant::now() + RTR_SOLICITATION_INTERVAL);
            let expire_deadline = self.next_expiry();

            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    let (n, src) = result?;
                    self.handle_packet(src, &buf[..n]).await?;
                    // A reply arrived; no more need to keep soliciting.
                    solicitations_sent = MAX_RTR_SOLICITATIONS;
                }
                event = self.events.recv() => {
                    let Some(event) = event else { break };
                    self.handle_netlink_event(event).await?;
                }
                _ = Self::wait(rs_deadline) => {
                    self.send_rs().await?;
                    solicitations_sent += 1;
                }
                _ = Self::wait(expire_deadline) => {
                    let events = self.router_list.expire(Instant::now());
                    for event in events {
                        self.apply(event).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// The soonest known prefix/router expiry, if any, so `run`'s select
    /// loop only wakes for it instead of polling on a fixed interval.
    fn next_expiry(&self) -> Option<Instant> {
        self.router_list
            .routers()
            .iter()
            .flat_map(|r| {
                r.prefixes
                    .iter()
                    .map(|p| p.valid_until)
                    .chain(r.default_until)
            })
            .min()
    }

    async fn wait(deadline: Option<Instant>) {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending().await,
        }
    }

    async fn send_rs(&self) -> Result<(), Error> {
        let mac = match &self.iid_scheme {
            IidScheme::Eui64 { mac } => Some(*mac),
            IidScheme::Rfc7217 { .. } => None,
        };
        let bytes = ndp::build_router_solicitation(mac.as_ref());
        self.socket.send_to(ALL_ROUTERS_MULTICAST, &bytes).await?;
        Ok(())
    }

    async fn handle_packet(&mut self, src: std::net::Ipv6Addr, buf: &[u8]) -> Result<(), Error> {
        let Some(ra) = RouterAdvertisement::parse(buf) else {
            return Ok(());
        };
        let events = self
            .router_list
            .handle_ra(src, &ra, buf, Instant::now(), |pio, dad| {
                self.iid_scheme.make_iid(pio, dad)
            });
        for event in events {
            self.apply(event).await?;
        }
        Ok(())
    }

    async fn handle_netlink_event(&mut self, event: NetlinkEvent) -> Result<(), Error> {
        let NetlinkEvent::AddrDadFailed {
            ifindex,
            address: IpAddr::V6(address),
            ..
        } = event
        else {
            return Ok(());
        };
        if ifindex != self.ifindex {
            return Ok(());
        }
        let events = self
            .router_list
            .handle_dad_failure(address, Instant::now(), |pio, dad| {
                self.iid_scheme.make_iid(pio, dad)
            });
        for event in events {
            self.apply(event).await?;
        }
        Ok(())
    }

    async fn apply(&self, event: RaEvent) -> Result<(), Error> {
        match event {
            RaEvent::ConfigureAddress {
                address,
                prefix_len,
                valid_secs,
                preferred_secs,
            } => {
                self.netlink
                    .add_addr_with_lifetime(
                        self.ifindex,
                        IpAddr::V6(address),
                        prefix_len,
                        valid_secs,
                        preferred_secs,
                    )
                    .await?;
                tracing::info!(%address, prefix_len, valid_secs, preferred_secs, "ipv6nd: configured SLAAC address");
            }
            RaEvent::RemoveAddress {
                address,
                prefix_len,
            } => {
                match self
                    .netlink
                    .del_addr(self.ifindex, IpAddr::V6(address), prefix_len)
                    .await
                {
                    Ok(()) => tracing::info!(%address, "ipv6nd: removed address"),
                    Err(e) => tracing::warn!(%address, "ipv6nd: failed to remove address: {e}"),
                }
            }
            RaEvent::AddDefaultRoute { gateway } => {
                match self
                    .netlink
                    .add_default_route_v6(self.ifindex, gateway)
                    .await
                {
                    Ok(()) => tracing::info!(%gateway, "ipv6nd: installed default route"),
                    Err(e) => {
                        tracing::warn!(%gateway, "ipv6nd: failed to install default route: {e}")
                    }
                }
            }
            RaEvent::RemoveDefaultRoute { gateway } => {
                match self
                    .netlink
                    .del_default_route_v6(self.ifindex, gateway)
                    .await
                {
                    Ok(()) => tracing::info!(%gateway, "ipv6nd: removed default route"),
                    Err(e) => {
                        tracing::warn!(%gateway, "ipv6nd: failed to remove default route: {e}")
                    }
                }
            }
            RaEvent::Dhcp6(trigger) => {
                tracing::info!(
                    ?trigger,
                    "ipv6nd: dhcp6 trigger (DHCPv6 not implemented yet)"
                );
            }
            RaEvent::ApplyLinkParameters {
                hop_limit,
                reachable_time_ms,
                retrans_timer_ms,
            } => {
                if let Err(e) = sysctl::set_hop_limit(&self.ifname, hop_limit).await {
                    tracing::warn!("ipv6nd: failed to set hop_limit: {e}");
                }
                if let Err(e) =
                    sysctl::set_neighbor_timers(&self.ifname, reachable_time_ms, retrans_timer_ms)
                        .await
                {
                    tracing::warn!("ipv6nd: failed to set neighbor timers: {e}");
                }
            }
        }
        Ok(())
    }
}
