//! Raw `AF_INET6`/`SOCK_RAW`/`IPPROTO_ICMPV6` sockets for Router
//! Solicitation/Advertisement (RFC 4861). Unlike the `AF_PACKET` path
//! DHCPv4 needs (see `oxipd_net::packet`), the kernel builds the IPv6
//! header for us here — oxipd only builds/parses the ICMPv6 payload
//! itself (see `oxipd_proto::ndp`), and the checksum needs the real
//! source address the kernel will pick, so unlike DHCPv4 there's no
//! benefit to computing it by hand — the kernel does this automatically
//! for raw ICMPv6 sockets.
//!
//! Scoped to one interface via `IPV6_MULTICAST_IF` (egress) and joining
//! `ff02::2` "all routers" on that interface's index (ingress); this
//! covers the overwhelming majority of real RA traffic (multicast). A
//! router replying with a *unicast* RA to the soliciting address isn't
//! filtered to one interface this way — full source-interface pinning
//! would need `IPV6_PKTINFO` ancillary data, deferred for now.

use std::io;
use std::mem;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

pub const IPPROTO_ICMPV6: libc::c_int = 58;
pub const ICMP6_ROUTER_SOLICIT: u8 = 133;
pub const ICMP6_ROUTER_ADVERT: u8 = 134;

/// `ICMP6_FILTER`'s sockopt name (from `<netinet/icmp6.h>`; not exposed by
/// the `libc` crate for Linux).
const ICMP6_FILTER: libc::c_int = 1;

pub const ALL_ROUTERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// RFC 3542 §5.2's `icmp6_filter`: a 256-bit bitmap, one bit per ICMPv6
/// type, set = blocked.
#[repr(C)]
struct Icmp6Filter {
    filt: [u32; 8],
}

impl Icmp6Filter {
    fn block_all() -> Self {
        Icmp6Filter { filt: [0xffff_ffff; 8] }
    }

    fn set_pass(&mut self, icmp_type: u8) {
        let idx = (icmp_type >> 5) as usize;
        let bit = icmp_type & 31;
        self.filt[idx] &= !(1u32 << bit);
    }
}

/// Open, filter (only Router Advertisements, type 134, pass), and scope
/// to `ifindex` — as a plain blocking syscall sequence with no tokio
/// dependency, so the privileged helper can call it directly (mirrors
/// `oxipd_net::packet::open_raw_fd`).
pub fn open_raw_fd(ifindex: i32) -> Result<OwnedFd, Error> {
    // SAFETY: constant, valid arguments; the raw fd is checked for -1
    // immediately below before being wrapped in an OwnedFd.
    let raw = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            IPPROTO_ICMPV6,
        )
    };
    if raw < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` was just returned by socket(2) and validated above.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = owned.as_raw_fd();

    let mut filter = Icmp6Filter::block_all();
    filter.set_pass(ICMP6_ROUTER_ADVERT);
    setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter)?;

    let mcast_if: libc::c_uint = ifindex as libc::c_uint;
    setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &mcast_if)?;

    let hops: libc::c_int = 255;
    setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &hops)?;

    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: ALL_ROUTERS_MULTICAST.octets(),
        },
        ipv6mr_interface: ifindex as libc::c_uint,
    };
    setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)?;

    Ok(owned)
}

fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a valid, initialized `T` for the duration of
    // this call; setsockopt reads exactly `size_of::<T>()` bytes from it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// A non-blocking raw ICMPv6 socket bound to one interface.
pub struct RawIcmp6Socket {
    fd: AsyncFd<OwnedFd>,
    ifindex: i32,
}

impl RawIcmp6Socket {
    pub fn open(ifindex: i32) -> Result<Self, Error> {
        let owned = open_raw_fd(ifindex)?;
        Self::from_owned_fd(owned, ifindex)
    }

    /// Wrap an already-open-and-configured fd (e.g. handed over from the
    /// privileged helper). Must be called from within a running tokio
    /// reactor.
    pub fn from_owned_fd(owned: OwnedFd, ifindex: i32) -> Result<Self, Error> {
        Ok(RawIcmp6Socket {
            fd: AsyncFd::new(owned)?,
            ifindex,
        })
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    pub async fn send_to(&self, dst: Ipv6Addr, payload: &[u8]) -> Result<usize, Error> {
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| send_icmp6(fd, self.ifindex, dst, payload)) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ipv6Addr), Error> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| recv_icmp6(fd, buf)) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }
}

fn send_icmp6(fd: RawFd, ifindex: i32, dst: Ipv6Addr, payload: &[u8]) -> io::Result<usize> {
    // SAFETY: zero-initializing sockaddr_in6 is valid; every field is
    // either left zero or explicitly set below before use.
    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as u16;
    addr.sin6_addr = libc::in6_addr { s6_addr: dst.octets() };
    if dst.is_multicast() {
        addr.sin6_scope_id = ifindex as u32;
    }

    // SAFETY: `addr` is valid for its declared size, `payload` is a valid
    // slice for its own length; sendto does not retain either pointer.
    let rc = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

fn recv_icmp6(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Ipv6Addr)> {
    // SAFETY: see send_icmp6's zeroing rationale above.
    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut addrlen = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    // SAFETY: `buf` is a valid writable slice; `addr`/`addrlen` are valid
    // for recvfrom(2) to fill in up to `addrlen` bytes.
    let rc = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut libc::sockaddr_in6 as *mut libc::sockaddr,
            &mut addrlen,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((rc as usize, Ipv6Addr::from(addr.sin6_addr.s6_addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_blocks_everything_except_the_passed_type() {
        let mut filter = Icmp6Filter::block_all();
        filter.set_pass(ICMP6_ROUTER_ADVERT);

        for t in 0u16..256 {
            let t = t as u8;
            let idx = (t >> 5) as usize;
            let bit = t & 31;
            let blocked = filter.filt[idx] & (1u32 << bit) != 0;
            if t == ICMP6_ROUTER_ADVERT {
                assert!(!blocked, "RA (134) must be passed");
            } else {
                assert!(blocked, "type {t} must be blocked");
            }
        }
    }

    #[test]
    fn all_routers_multicast_is_ff02_colon_2() {
        assert_eq!(ALL_ROUTERS_MULTICAST, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
        assert!(ALL_ROUTERS_MULTICAST.is_multicast());
    }
}
