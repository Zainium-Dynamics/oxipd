//! Privilege separation between the unprivileged `engine` process (owns
//! every DHCP/ARP/ND state machine and parses all untrusted network input)
//! and a privileged helper process (does only mechanical operations the
//! engine requests: opening raw sockets, netlink mutations, running hook
//! scripts, lease-file I/O). See PLAN.md's "Process / privilege model"
//! section for the full rationale.
//!
//! Module map:
//! - [`channel`]: the `SOCK_SEQPACKET` + `SCM_RIGHTS` transport.
//! - [`proto`]: the tagged request/response protocol sent over it.
//! - [`spawn`]: forks the helper process before any tokio runtime exists.
//! - [`privileges`]: drops the helper down to the minimum Linux
//!   capabilities it needs.
//! - [`helper`]: the privileged, synchronous dispatch loop.
//! - [`client`]: the unprivileged, async request client.

pub mod channel;
pub mod client;
pub mod helper;
pub mod privileges;
pub mod proto;
pub mod spawn;
