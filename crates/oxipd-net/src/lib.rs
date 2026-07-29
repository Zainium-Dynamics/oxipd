//! Linux network integration: rtnetlink client, raw `AF_PACKET`/ICMPv6
//! sockets, and checksum helpers.
//!
//! The ICMPv6 raw-socket helper (needed for IPv6 Router Solicitation/
//! Advertisement in M4) is not implemented yet.

pub mod checksum;
pub mod icmp6;
pub mod netlink;
pub mod packet;
pub mod sysctl;
