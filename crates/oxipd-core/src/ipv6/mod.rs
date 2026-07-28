//! IPv6 address management: SLAAC interface-identifier generation lives
//! here ([`slaac`]); the per-interface address bookkeeping (tracking every
//! configured address regardless of source, mirroring dhcpcd's
//! `ipv4_state`/`ipv6_state`) is a follow-up increment.

pub mod slaac;
