//! The tagged request/response protocol spoken over an
//! [`crate::channel`], serialized with `postcard`. Deliberately a small,
//! enumerated set of concrete operations (`OpenPacketSocket`, ...) rather
//! than dhcpcd's `ps_msghdr` approach of proxying an arbitrary `sendmsg`/
//! `ioctl` call — see PLAN.md's process/privilege model section.
//!
//! Any file descriptor a response carries (e.g. a freshly opened raw
//! socket) travels in the channel message's `SCM_RIGHTS` ancillary data,
//! never inside these enums themselves.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Round-trip liveness/wiring check; expects [`Response::Pong`].
    Ping,
    /// Open and bind a raw `AF_PACKET`/`SOCK_RAW` socket on `ifindex`,
    /// scoped to `ethertype` (see `oxipd_net::packet::open_raw_fd`).
    /// Expects [`Response::Fd`] with the socket attached.
    OpenPacketSocket { ifindex: i32, ethertype: u16 },
    /// Ask the helper to exit its dispatch loop.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    /// A file descriptor was opened and is attached to this message's
    /// `SCM_RIGHTS` data.
    Fd,
    ShuttingDown,
    Error(String),
}
