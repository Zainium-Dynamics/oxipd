//! Linux network integration: rtnetlink client, raw `AF_PACKET`/ICMPv6
//! sockets, and checksum helpers.
//!
//! Only [`checksum`] is implemented so far (M1 milestone in progress); the
//! netlink and raw-socket modules land next.

pub mod checksum;
