//! The engine-side (unprivileged, async) half of a privsep channel: a
//! typed request/response client wrapping [`crate::channel`] in a tokio
//! `AsyncFd`, mirroring the readiness-loop pattern `oxipd_net::packet`
//! uses for its raw sockets.

use std::os::fd::{AsRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

use crate::channel;
use crate::proto::{Request, Response};

const MAX_MESSAGE_LEN: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("channel error: {0}")]
    Channel(#[from] channel::Error),
    #[error("failed to encode request: {0}")]
    Encode(postcard::Error),
    #[error("failed to decode response: {0}")]
    Decode(postcard::Error),
    #[error("privileged helper reported an error: {0}")]
    Helper(String),
    #[error("received an unexpected response for this request")]
    UnexpectedResponse,
    #[error("expected a file descriptor in the response but none was received")]
    MissingFd,
}

fn to_io(e: channel::Error) -> std::io::Error {
    match e {
        channel::Error::Io(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

/// A handle to the privileged helper process, usable from async code in
/// the unprivileged engine.
pub struct PrivsepClient {
    fd: AsyncFd<OwnedFd>,
}

impl PrivsepClient {
    /// Wrap the engine's end of a [`crate::channel::socketpair`]. Must be
    /// called from within a running tokio reactor.
    pub fn new(fd: OwnedFd) -> std::io::Result<Self> {
        channel::set_nonblocking(fd.as_raw_fd())?;
        Ok(PrivsepClient { fd: AsyncFd::new(fd)? })
    }

    async fn call(&self, req: &Request) -> Result<(Response, Vec<OwnedFd>), Error> {
        let bytes = postcard::to_stdvec(req).map_err(Error::Encode)?;

        loop {
            let mut guard = self.fd.writable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| channel::send_msg(fd, &bytes, &[]).map_err(to_io)) {
                Ok(result) => {
                    result?;
                    break;
                }
                Err(_would_block) => continue,
            }
        }

        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| channel::recv_msg(fd, &mut buf).map_err(to_io)) {
                Ok(result) => {
                    let (n, fds) = result?;
                    let resp = postcard::from_bytes(&buf[..n]).map_err(Error::Decode)?;
                    return Ok((resp, fds));
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Round-trip liveness check.
    pub async fn ping(&self) -> Result<(), Error> {
        match self.call(&Request::Ping).await?.0 {
            Response::Pong => Ok(()),
            Response::Error(e) => Err(Error::Helper(e)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Ask the helper to open a raw `AF_PACKET` socket and hand back its
    /// fd. The caller typically wraps the result with
    /// `oxipd_net::packet::RawSocket::from_owned_fd`.
    pub async fn open_packet_socket(&self, ifindex: i32, ethertype: u16) -> Result<OwnedFd, Error> {
        let (resp, mut fds) = self.call(&Request::OpenPacketSocket { ifindex, ethertype }).await?;
        match resp {
            Response::Fd => fds.pop().ok_or(Error::MissingFd),
            Response::Error(e) => Err(Error::Helper(e)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Ask the helper to exit its dispatch loop.
    pub async fn shutdown(&self) -> Result<(), Error> {
        match self.call(&Request::Shutdown).await?.0 {
            Response::ShuttingDown => Ok(()),
            Response::Error(e) => Err(Error::Helper(e)),
            _ => Err(Error::UnexpectedResponse),
        }
    }
}
