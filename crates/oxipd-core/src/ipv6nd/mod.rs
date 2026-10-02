//! Router Advertisement processing: the pure decisions
//! `oxipd_proto::ndp::RouterAdvertisement` data feeds into (this module),
//! plus the stateful router-list/prefix-lifecycle engine built on top of
//! them ([`router_list`]). The raw ICMPv6 socket I/O is a separate,
//! not-yet-implemented layer — same pure-core-first approach as `dhcp4`.
//! This is the highest-logic-risk part of the IPv6 stack per PLAN.md's
//! research (RA processing is "essentially its own small protocol
//! stack"), so it's where the tests matter most.

pub mod client;
pub mod router_list;

pub use client::{IidScheme, Ipv6NdClient};
pub use router_list::{RaEvent, Router, RouterList};

/// RFC 4862 §5.5.3.e: a received prefix's valid lifetime must never be
/// used to shorten an existing address's remaining lifetime below this
/// floor in one step — protects against a spoofed/misconfigured RA
/// flash-expiring addresses.
pub const MIN_EXTENDED_VALID_LIFETIME_SECS: u32 = 7200;

/// What a Router Advertisement's M/O flags say the host should do about
/// DHCPv6, per RFC 4861 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp6Trigger {
    /// Neither flag set: no DHCPv6 involvement.
    None,
    /// 'M' (Managed) set: run stateful DHCPv6 (address assignment).
    Stateful,
    /// 'O' (Other) set, 'M' clear: run stateless DHCPv6 (options only).
    Stateless,
}

/// Map an RA's M/O flags to the DHCPv6 mode a host should start, per
/// RFC 4861 §4.2 (M takes priority over O when both are set).
pub fn dhcp6_trigger(managed: bool, other_config: bool) -> Dhcp6Trigger {
    if managed {
        Dhcp6Trigger::Stateful
    } else if other_config {
        Dhcp6Trigger::Stateless
    } else {
        Dhcp6Trigger::None
    }
}

/// RFC 4862 §5.5.3.e: compute the valid lifetime to actually apply to an
/// existing SLAAC address given a newly received Prefix Information
/// option's valid lifetime. `remaining_secs` is `None` for a prefix with
/// no existing address yet (in which case the received value is always
/// used directly).
///
/// The rule exists so a single (possibly spoofed, possibly just
/// misconfigured) RA can't abruptly expire an address: a lifetime
/// decrease is only ever accepted down to a 2-hour floor per step. If the
/// address is already within that floor, the update is ignored entirely
/// (the existing `remaining` value is kept) rather than honoring a
/// smaller — or zero — received value; the RFC's intent is that genuine
/// deprecation happens gradually, as real time elapses between
/// advertisements, not by a router's claim alone. The only way this
/// function itself returns `0` is for a prefix with no prior sighting
/// (`remaining_secs: None`) whose received valid lifetime already is `0`.
pub fn effective_valid_lifetime(
    remaining_secs: Option<u32>,
    received_valid_lifetime_secs: u32,
) -> u32 {
    let Some(remaining) = remaining_secs else {
        return received_valid_lifetime_secs;
    };
    if received_valid_lifetime_secs > MIN_EXTENDED_VALID_LIFETIME_SECS
        || received_valid_lifetime_secs > remaining
    {
        received_valid_lifetime_secs
    } else if remaining <= MIN_EXTENDED_VALID_LIFETIME_SECS {
        remaining
    } else {
        MIN_EXTENDED_VALID_LIFETIME_SECS
    }
}

/// Whether this RA's content actually differs from the last one seen from
/// the same router — used to avoid re-triggering DHCPv6 startup (or other
/// "did anything change" logic) on every periodic, identical RA.
pub fn ra_changed(previous: Option<&[u8]>, current: &[u8]) -> bool {
    previous != Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp6_trigger_prioritizes_managed_over_other() {
        assert_eq!(dhcp6_trigger(true, true), Dhcp6Trigger::Stateful);
        assert_eq!(dhcp6_trigger(true, false), Dhcp6Trigger::Stateful);
        assert_eq!(dhcp6_trigger(false, true), Dhcp6Trigger::Stateless);
        assert_eq!(dhcp6_trigger(false, false), Dhcp6Trigger::None);
    }

    #[test]
    fn new_prefix_uses_received_lifetime_directly() {
        assert_eq!(effective_valid_lifetime(None, 60), 60);
        assert_eq!(effective_valid_lifetime(None, 0), 0);
    }

    #[test]
    fn lifetime_increase_is_always_applied() {
        assert_eq!(effective_valid_lifetime(Some(100), 5000), 5000);
    }

    #[test]
    fn lifetime_over_two_hours_is_always_applied_even_if_shorter_than_remaining() {
        // received (7300s) > remaining (10000s)? No -- but received still
        // exceeds the 2h floor, so RFC4862 case 1 applies regardless.
        assert_eq!(effective_valid_lifetime(Some(10_000), 7300), 7300);
    }

    #[test]
    fn already_within_floor_ignores_further_shortening() {
        // remaining <= 2h: the RFC says ignore further shortening
        // attempts by keeping `remaining` unchanged, even if the newly
        // received value is smaller, or 0.
        assert_eq!(effective_valid_lifetime(Some(3600), 0), 3600);
        assert_eq!(effective_valid_lifetime(Some(7200), 100), 7200);
    }

    #[test]
    fn shortening_below_the_floor_is_clamped_to_two_hours() {
        assert_eq!(
            effective_valid_lifetime(Some(10_000), 100),
            MIN_EXTENDED_VALID_LIFETIME_SECS
        );
    }

    #[test]
    fn ra_changed_detects_first_sighting_and_real_changes() {
        assert!(ra_changed(None, b"abc"));
        assert!(ra_changed(Some(b"abc"), b"abd"));
        assert!(!ra_changed(Some(b"abc"), b"abc"));
    }
}
