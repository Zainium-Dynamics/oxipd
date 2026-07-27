//! `AF_UNIX SOCK_SEQPACKET` message channel with `SCM_RIGHTS` file
//! descriptor passing.
//!
//! `SOCK_SEQPACKET` (rather than `SOCK_STREAM`) is message-oriented like
//! `SOCK_DGRAM`, so a single `sendmsg`/`recvmsg` call is exactly one
//! logical request or response — no manual length-prefix framing needed,
//! unlike a stream socket. This is the transport between the unprivileged
//! `engine` and the privileged helper (see the module-level docs in
//! `lib.rs`); fd-passing is how the helper hands back sockets it opened on
//! the engine's behalf (raw `AF_PACKET`/ICMPv6 sockets) without the engine
//! ever needing the privileges required to open them itself.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Maximum file descriptors carried in one message. Bounded so the control
/// message buffer can be a fixed, small allocation.
pub const MAX_FDS: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("peer closed the channel")]
    Closed,
    #[error("control message truncated: too many file descriptors in one message")]
    ControlTruncated,
}

/// Create a connected pair of `SOCK_SEQPACKET` file descriptors.
pub fn socketpair() -> Result<(OwnedFd, OwnedFd), Error> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid, appropriately-sized output array for
    // socketpair(2).
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    // SAFETY: both fds were just returned by a successful socketpair(2)
    // call and are owned exclusively by this function's caller from here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Set `O_NONBLOCK` on a file descriptor. Only the engine-side end of a
/// pair needs this (see [`crate::client`]); the helper-side end stays
/// blocking since it runs a simple synchronous loop.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid, open file descriptor for the duration of
    // this call, and F_GETFL/F_SETFL do not retain any pointer arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send `data` as one `SOCK_SEQPACKET` message, optionally carrying file
/// descriptors as `SCM_RIGHTS` ancillary data.
pub fn send_msg(fd: RawFd, data: &[u8], out_fds: &[RawFd]) -> Result<(), Error> {
    debug_assert!(out_fds.len() <= MAX_FDS);

    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    // SAFETY: zero-initializing msghdr is valid; every field is either a
    // plain-old-data integer or a pointer we explicitly set before use.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;

    // Must outlive `msg` below, hence declared here even though it's only
    // populated inside the `if`.
    let mut cmsg_buf: Vec<u8>;
    if !out_fds.is_empty() {
        let fds_bytes = mem::size_of_val(out_fds) as u32;
        // SAFETY: CMSG_SPACE has no preconditions beyond a valid u32 input.
        let space = unsafe { libc::CMSG_SPACE(fds_bytes) } as usize;
        cmsg_buf = vec![0u8; space];
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space;

        // SAFETY: `cmsg_buf` is exactly `CMSG_SPACE(fds_bytes)` bytes and
        // zero-initialized, so CMSG_FIRSTHDR/CMSG_DATA stay within it; the
        // fd bytes copied in are plain `RawFd` (i32) values.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes) as usize;
            std::ptr::copy_nonoverlapping(
                out_fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                fds_bytes as usize,
            );
        }
    }

    // SAFETY: `msg` is fully initialized and its buffers (`iov`,
    // `cmsg_buf`) outlive this call.
    let rc = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
    if rc < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Receive one message into `buf`, returning the byte count and any file
/// descriptors carried alongside it. Returns [`Error::Closed`] on EOF
/// (peer closed its end).
pub fn recv_msg(fd: RawFd, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>), Error> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let fds_bytes = (MAX_FDS * mem::size_of::<RawFd>()) as u32;
    // SAFETY: CMSG_SPACE has no preconditions beyond a valid u32 input.
    let space = unsafe { libc::CMSG_SPACE(fds_bytes) } as usize;
    let mut cmsg_buf = vec![0u8; space];

    // SAFETY: see send_msg's zeroing rationale above.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space;

    // SAFETY: `msg` is fully initialized; `buf` and `cmsg_buf` are valid,
    // writable buffers of the declared lengths that outlive this call.
    let rc = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if rc < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    if rc == 0 {
        return Err(Error::Closed);
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(Error::ControlTruncated);
    }

    let mut fds = Vec::new();
    // SAFETY: `msg` was filled in by the successful recvmsg(2) above, so
    // CMSG_FIRSTHDR/CMSG_DATA read within `cmsg_buf`'s bounds. We only
    // read `cmsg_len` after checking the header is non-null, and we never
    // call CMSG_NXTHDR since oxipd only ever sends a single SCM_RIGHTS
    // header per message (no multi-cmsg chaining to walk).
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null() {
            let cmsg_ref = &*cmsg;
            if cmsg_ref.cmsg_level == libc::SOL_SOCKET && cmsg_ref.cmsg_type == libc::SCM_RIGHTS {
                let hdr_len = libc::CMSG_LEN(0) as usize;
                let data_len = cmsg_ref.cmsg_len.saturating_sub(hdr_len);
                let n_fds = data_len / mem::size_of::<RawFd>();
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..n_fds {
                    let raw = std::ptr::read_unaligned(data_ptr.add(i));
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
        }
    }

    Ok((rc as usize, fds))
}

/// A blocking `SOCK_SEQPACKET` + `SCM_RIGHTS` channel end. Used by the
/// privileged helper, which is deliberately a simple synchronous loop
/// (fewer moving parts on the security-sensitive side).
pub struct BlockingChannel(OwnedFd);

impl BlockingChannel {
    pub fn new(fd: OwnedFd) -> Self {
        BlockingChannel(fd)
    }

    pub fn send(&self, data: &[u8], fds: &[RawFd]) -> Result<(), Error> {
        send_msg(self.0.as_raw_fd(), data, fds)
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>), Error> {
        recv_msg(self.0.as_raw_fd(), buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    #[test]
    fn round_trips_data_only() {
        let (a, b) = socketpair().unwrap();
        let a = BlockingChannel::new(a);
        let b = BlockingChannel::new(b);

        a.send(b"hello", &[]).unwrap();
        let mut buf = [0u8; 64];
        let (n, fds) = b.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fds.is_empty());
    }

    #[test]
    fn round_trips_a_file_descriptor() {
        let (a, b) = socketpair().unwrap();
        let a = BlockingChannel::new(a);
        let b = BlockingChannel::new(b);

        // Hand a pipe's read-end fd across the channel and confirm the
        // *data* written into the pipe on our side is readable from the
        // received fd on the other side — proving it's a real dup of the
        // same underlying open file description, not just a copied number.
        let (pr, pw) = {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            (fds[0], fds[1])
        };

        a.send(b"fd-attached", &[pr]).unwrap();
        // Close our copy of the read end; only the copy handed over the
        // channel (and now owned by `b`'s recv result) should keep it alive.
        unsafe {
            libc::close(pr);
        }

        let mut buf = [0u8; 64];
        let (n, fds) = b.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"fd-attached");
        assert_eq!(fds.len(), 1);

        let received_read_fd = fds.into_iter().next().unwrap().into_raw_fd();
        unsafe {
            libc::write(pw, b"payload".as_ptr() as *const libc::c_void, 7);
            libc::close(pw);
        }
        let mut readback = [0u8; 16];
        let n = unsafe { libc::read(received_read_fd, readback.as_mut_ptr() as *mut libc::c_void, 16) };
        assert_eq!(&readback[..n as usize], b"payload");
        unsafe {
            libc::close(received_read_fd);
        }
    }

    #[test]
    fn recv_on_closed_peer_reports_closed() {
        let (a, b) = socketpair().unwrap();
        drop(a);
        let b = BlockingChannel::new(b);
        let mut buf = [0u8; 16];
        match b.recv(&mut buf) {
            Err(Error::Closed) => {}
            other => panic!("expected Closed, got {other:?}"),
        }
    }
}
