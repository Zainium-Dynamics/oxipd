//! Raw `AF_PACKET`/`SOCK_RAW` link-layer sockets, for the pre-address-bind
//! window DHCPv4 needs (see oxipd-core::dhcp4) and for ARP.
//!
//! Unlike dhcpcd's `bpf.c`, no kernel-side classic-BPF filter is attached.
//! dhcpcd's own code comments note it re-validates every packet in
//! userspace regardless of the kernel filter's outcome, and the socket is
//! already scoped to one EtherType via the `protocol` argument to
//! `socket(2)` (Linux delivers only matching-EtherType frames to a packet
//! socket bound that way) — so we get equivalent scoping without the
//! cBPF-bytecode-generation machinery `bpf.c` needs to stay portable to
//! BSD's `/dev/bpf`.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_ALEN: usize = 6;
pub const ETH_HLEN: usize = 14;

pub type MacAddr = [u8; ETH_ALEN];
pub const BROADCAST_MAC: MacAddr = [0xff; ETH_ALEN];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Prepend a 14-byte Ethernet header to `payload`. Pure/allocation-only, so
/// it's unit-testable without a real socket.
pub fn build_ethernet_frame(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_HLEN + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A parsed Ethernet header + a borrowed view of the payload that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Parse a raw captured frame. Returns `None` if it's shorter than a
/// minimal Ethernet header (never panics on malformed/truncated input).
pub fn parse_ethernet_frame(frame: &[u8]) -> Option<EthernetFrame<'_>> {
    if frame.len() < ETH_HLEN {
        return None;
    }
    let mut dst = [0u8; ETH_ALEN];
    let mut src = [0u8; ETH_ALEN];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some(EthernetFrame {
        dst,
        src,
        ethertype,
        payload: &frame[ETH_HLEN..],
    })
}

/// Open and bind a raw `AF_PACKET`/`SOCK_RAW` socket, as a plain blocking
/// syscall sequence with no tokio dependency. This is the half oxipd's
/// privileged helper process calls directly (it has no reactor and
/// shouldn't need one just to open a socket and hand off the fd) — see
/// [`RawSocket::open`] for the tokio-wrapped, non-blocking version used
/// once a socket is owned by the async engine process.
pub fn open_raw_fd(ifindex: i32, ethertype: u16) -> Result<OwnedFd, Error> {
    // SAFETY: constant, valid arguments; the raw fd is checked for -1
    // immediately below before being wrapped in an OwnedFd.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(ethertype.to_be()),
        )
    };
    if raw < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` was just returned by socket(2) and validated above,
    // and is not used again except through the OwnedFd.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ethertype.to_be();
    addr.sll_ifindex = ifindex;

    // SAFETY: `addr` is a valid, fully-initialized sockaddr_ll of the
    // correct size for bind(2).
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    Ok(owned)
}

/// A non-blocking `AF_PACKET`/`SOCK_RAW` socket bound to one interface and
/// scoped to one EtherType.
pub struct RawSocket {
    fd: AsyncFd<OwnedFd>,
    ifindex: i32,
}

impl RawSocket {
    /// Open and bind a raw socket on `ifindex`, receiving only frames of
    /// `ethertype` (e.g. [`ETH_P_ARP`] or [`ETH_P_IP`]).
    ///
    /// Requires `CAP_NET_RAW` (or root); in oxipd's process model this is
    /// called from the privileged helper (see oxipd-privsep), which then
    /// hands the bound fd to the unprivileged engine via `SCM_RIGHTS` (see
    /// [`Self::from_owned_fd`] for the engine side of that handoff).
    pub fn open(ifindex: i32, ethertype: u16) -> Result<Self, Error> {
        let owned = open_raw_fd(ifindex, ethertype)?;
        Self::from_owned_fd(owned, ifindex)
    }

    /// Wrap an already-open-and-bound raw socket fd (e.g. one received
    /// over oxipd-privsep's `SCM_RIGHTS` channel from the privileged
    /// helper) for async use in this process. Must be called from within a
    /// running tokio reactor.
    pub fn from_owned_fd(owned: OwnedFd, ifindex: i32) -> Result<Self, Error> {
        Ok(RawSocket {
            fd: AsyncFd::new(owned)?,
            ifindex,
        })
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Send a fully-formed Ethernet frame (see [`build_ethernet_frame`]).
    pub async fn send_frame(&self, frame: &[u8]) -> Result<usize, Error> {
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| send_raw(fd, self.ifindex, frame)) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive one raw frame (Ethernet header included). `buf` should be at
    /// least MTU + `ETH_HLEN` sized.
    pub async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| recv_raw(fd, buf)) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }
}

fn send_raw(fd: RawFd, ifindex: i32, frame: &[u8]) -> io::Result<usize> {
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN as u8;

    // SAFETY: `addr` is valid for its declared size, `frame` is a valid
    // slice for its own length; sendto does not retain either pointer.
    let rc = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

fn recv_raw(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is a valid, writable slice for its own length; recv
    // writes at most that many bytes and does not retain the pointer.
    let rc = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_frame_round_trips() {
        let dst = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let src = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let payload = b"hello dhcp";
        let frame = build_ethernet_frame(dst, src, ETH_P_IP, payload);

        let parsed = parse_ethernet_frame(&frame).expect("parses");
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.ethertype, ETH_P_IP);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn short_frame_does_not_panic() {
        assert_eq!(parse_ethernet_frame(&[0u8; 5]), None);
    }

    #[test]
    fn broadcast_mac_is_all_ones() {
        assert_eq!(BROADCAST_MAC, [0xff; 6]);
    }
}
