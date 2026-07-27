//! `oxipd` — a DHCPv4/DHCPv6/IPv6-RA client daemon for Linux.
//!
//! This is a scaffold: milestone M0 (`oxipd-proto`'s DHCPv4 codec) and part
//! of M1 (`oxipd-net`'s checksum helpers) are implemented and tested; the
//! daemon itself (netlink integration, privilege separation, the protocol
//! state machines, and the control socket) lands in the milestones tracked
//! in this repo's plan.

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("oxipd: scaffold only, no protocol state machines wired up yet");
    Ok(())
}
