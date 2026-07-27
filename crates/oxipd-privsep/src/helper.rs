//! The privileged helper's dispatch loop: a plain synchronous `recv` →
//! handle → `send` cycle, with no tokio runtime and no parsing of
//! untrusted network input (that all happens in the unprivileged engine —
//! see PLAN.md's process/privilege model section for why the split is
//! drawn here).

use std::os::fd::IntoRawFd;

use crate::channel::BlockingChannel;
use crate::proto::{Request, Response};

const MAX_MESSAGE_LEN: usize = 8192;

/// Run the helper's request loop until the engine disconnects or sends
/// [`Request::Shutdown`]. Intended to be called immediately after `fork()`
/// in the child, after privileges have been dropped to the minimum needed
/// (see [`crate::privileges`]).
pub fn run(channel: BlockingChannel) {
    let mut buf = vec![0u8; MAX_MESSAGE_LEN];
    loop {
        let (n, _fds) = match channel.recv(&mut buf) {
            Ok(v) => v,
            Err(crate::channel::Error::Closed) => {
                tracing::debug!("privsep helper: engine disconnected, exiting");
                return;
            }
            Err(e) => {
                tracing::warn!("privsep helper: recv failed: {e}");
                return;
            }
        };

        let request: Request = match postcard::from_bytes(&buf[..n]) {
            Ok(r) => r,
            Err(e) => {
                send_error(&channel, format!("malformed request: {e}"));
                continue;
            }
        };

        match request {
            Request::Ping => send(&channel, &Response::Pong, &[]),
            Request::Shutdown => {
                send(&channel, &Response::ShuttingDown, &[]);
                return;
            }
            Request::OpenPacketSocket { ifindex, ethertype } => {
                match oxipd_net::packet::open_raw_fd(ifindex, ethertype) {
                    Ok(owned) => {
                        let raw = owned.into_raw_fd();
                        send(&channel, &Response::Fd, &[raw]);
                        // SAFETY: `raw` was handed to the peer via
                        // SCM_RIGHTS in `send` above (which dup's it into
                        // the receiving process); our copy must still be
                        // closed here or it leaks in this process.
                        unsafe { libc::close(raw) };
                    }
                    Err(e) => send_error(&channel, format!("open_packet_socket failed: {e}")),
                }
            }
        }
    }
}

fn send(channel: &BlockingChannel, resp: &Response, fds: &[std::os::fd::RawFd]) {
    match postcard::to_stdvec(resp) {
        Ok(bytes) => {
            if let Err(e) = channel.send(&bytes, fds) {
                tracing::warn!("privsep helper: send failed: {e}");
            }
        }
        Err(e) => tracing::warn!("privsep helper: failed to encode response: {e}"),
    }
}

fn send_error(channel: &BlockingChannel, message: String) {
    tracing::warn!("privsep helper: {message}");
    send(channel, &Response::Error(message), &[]);
}
