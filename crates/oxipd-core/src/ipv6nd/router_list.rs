//! The stateful half of RA processing: tracks every router/prefix
//! currently known (mirroring dhcpcd's `ctx->ra_routers` + per-router
//! `rap->addrs`), building on the pure policy functions in the parent
//! module (`dhcp6_trigger`, `effective_valid_lifetime`, `ra_changed`).
//!
//! Deliberately scoped for this increment: an RA's full prefix list is
//! merged in (RFC 4862 §5.5.3's add/extend/deprecate semantics), but a
//! prefix that simply stops being mentioned in a later, otherwise-changed
//! RA is not implicitly withdrawn — only an explicit valid-lifetime-zero
//! PIO or the whole router's own lifetime elapsing removes anything.
//! Real routers essentially never do this (they re-advertise every
//! active prefix on every RA), so it's a reasonable simplification to
//! revisit only if it turns out to matter in practice.

use std::net::Ipv6Addr;
use std::time::Duration;

use oxipd_proto::ndp::{PrefixInformation, RouterAdvertisement, OPT_PREFIX_INFORMATION};
use tokio::time::Instant;

use crate::ipv6::slaac;

use super::{dhcp6_trigger, effective_valid_lifetime, ra_changed, Dhcp6Trigger};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_until: Instant,
    pub preferred_until: Instant,
    /// The SLAAC address generated for this prefix, if `autonomous` and
    /// its interface identifier wasn't RFC 5453-reserved.
    pub address: Option<Ipv6Addr>,
}

impl Prefix {
    fn remaining_valid_secs(&self, now: Instant) -> Option<u32> {
        (self.valid_until > now).then(|| (self.valid_until - now).as_secs() as u32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Router {
    pub source: Ipv6Addr,
    last_data: Vec<u8>,
    pub managed: bool,
    pub other_config: bool,
    /// `None` if not currently usable as a default router (advertised
    /// lifetime was 0, or it has since elapsed).
    pub default_until: Option<Instant>,
    pub prefixes: Vec<Prefix>,
}

/// What the (not yet built) async shell should do in response to
/// processing a Router Advertisement or an expiry sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaEvent {
    /// Configure (or re-affirm, with updated lifetimes) a SLAAC address.
    ConfigureAddress {
        address: Ipv6Addr,
        prefix_len: u8,
        valid_secs: u32,
        preferred_secs: u32,
    },
    /// A previously configured address's prefix reached a zero valid
    /// lifetime and should be removed from the interface.
    RemoveAddress { address: Ipv6Addr },
    /// Start (or don't start) DHCPv6, per the RA's M/O flags.
    Dhcp6(Dhcp6Trigger),
    /// Push these RA-derived values onto the kernel's ND parameters (see
    /// `oxipd_net::sysctl::{set_hop_limit,set_neighbor_timers}`).
    ApplyLinkParameters {
        hop_limit: u8,
        reachable_time_ms: u32,
        retrans_timer_ms: u32,
    },
}

#[derive(Debug, Default)]
pub struct RouterList {
    routers: Vec<Router>,
}

impl RouterList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn routers(&self) -> &[Router] {
        &self.routers
    }

    /// Process one received RA. `make_iid` generates the SLAAC interface
    /// identifier for an autonomous prefix — the caller supplies it since
    /// it needs interface-specific state (MAC for EUI-64, or the RFC 7217
    /// secret + DAD counter) this module doesn't own.
    pub fn handle_ra(
        &mut self,
        source: Ipv6Addr,
        ra: &RouterAdvertisement,
        raw: &[u8],
        now: Instant,
        make_iid: impl Fn(&PrefixInformation) -> slaac::Iid,
    ) -> Vec<RaEvent> {
        let idx = match self.routers.iter().position(|r| r.source == source) {
            Some(i) => i,
            None => {
                self.routers.push(Router {
                    source,
                    last_data: Vec::new(),
                    managed: false,
                    other_config: false,
                    default_until: None,
                    prefixes: Vec::new(),
                });
                self.routers.len() - 1
            }
        };

        // Routers re-send periodically even with nothing new to say;
        // still refresh this router's own lifetime, but skip re-deriving
        // prefix/DHCPv6 events for byte-identical content.
        if !ra_changed(Some(&self.routers[idx].last_data), raw) {
            self.routers[idx].default_until = router_lifetime_until(ra, now);
            return Vec::new();
        }

        self.routers[idx].last_data = raw.to_vec();
        self.routers[idx].managed = ra.managed();
        self.routers[idx].other_config = ra.other_config();
        self.routers[idx].default_until = router_lifetime_until(ra, now);

        let mut events = vec![
            RaEvent::ApplyLinkParameters {
                hop_limit: ra.cur_hop_limit(),
                reachable_time_ms: ra.reachable_time_ms(),
                retrans_timer_ms: ra.retrans_timer_ms(),
            },
            RaEvent::Dhcp6(dhcp6_trigger(ra.managed(), ra.other_config())),
        ];

        for (otype, value) in ra.options() {
            if otype != OPT_PREFIX_INFORMATION {
                continue;
            }
            if let Some(pio) = PrefixInformation::parse(value) {
                events.extend(self.merge_prefix(idx, &pio, now, &make_iid));
            }
        }

        events
    }

    fn merge_prefix(
        &mut self,
        router_idx: usize,
        pio: &PrefixInformation,
        now: Instant,
        make_iid: &impl Fn(&PrefixInformation) -> slaac::Iid,
    ) -> Option<RaEvent> {
        let router = &mut self.routers[router_idx];
        let existing_idx = router
            .prefixes
            .iter()
            .position(|p| p.prefix == pio.prefix && p.prefix_len == pio.prefix_len);

        let remaining = existing_idx.and_then(|i| router.prefixes[i].remaining_valid_secs(now));
        let valid_secs = effective_valid_lifetime(remaining, pio.valid_lifetime_secs);

        if valid_secs == 0 {
            let i = existing_idx?;
            let removed = router.prefixes.remove(i);
            return removed.address.map(|address| RaEvent::RemoveAddress { address });
        }

        let valid_until = now + Duration::from_secs(valid_secs as u64);
        let preferred_secs = pio.preferred_lifetime_secs.min(valid_secs);
        let preferred_until = now + Duration::from_secs(preferred_secs as u64);

        let address = if pio.autonomous {
            let iid = make_iid(pio);
            (!slaac::is_reserved_iid(&iid)).then(|| slaac::make_address(pio.prefix, iid))
        } else {
            None
        };

        let event = address.map(|address| RaEvent::ConfigureAddress {
            address,
            prefix_len: pio.prefix_len,
            valid_secs,
            preferred_secs,
        });

        let new_prefix = Prefix {
            prefix: pio.prefix,
            prefix_len: pio.prefix_len,
            on_link: pio.on_link,
            autonomous: pio.autonomous,
            valid_until,
            preferred_until,
            address,
        };
        match existing_idx {
            Some(i) => router.prefixes[i] = new_prefix,
            None => router.prefixes.push(new_prefix),
        }

        event
    }

    /// Sweep for prefixes/routers whose lifetime has elapsed. Call
    /// periodically (e.g. driven by whichever known expiry is soonest).
    pub fn expire(&mut self, now: Instant) -> Vec<RaEvent> {
        let mut events = Vec::new();
        self.routers.retain_mut(|router| {
            router.prefixes.retain(|p| {
                if p.valid_until > now {
                    return true;
                }
                if let Some(address) = p.address {
                    events.push(RaEvent::RemoveAddress { address });
                }
                false
            });
            let router_dead = router.default_until.is_some_and(|t| t <= now) && router.prefixes.is_empty();
            !router_dead
        });
        events
    }
}

fn router_lifetime_until(ra: &RouterAdvertisement, now: Instant) -> Option<Instant> {
    let secs = ra.router_lifetime_secs();
    (secs != 0).then(|| now + Duration::from_secs(secs as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ra_bytes(flags: u8, router_lifetime: u16, pio: Option<(Ipv6Addr, u8, u32, u32, u8)>) -> Vec<u8> {
        let mut buf = vec![0u8; oxipd_proto::ndp::RA_FIXED_LEN];
        buf[0] = oxipd_proto::ndp::ICMP6_ROUTER_ADVERT;
        buf[4] = 64;
        buf[5] = flags;
        buf[6..8].copy_from_slice(&router_lifetime.to_be_bytes());
        buf[8..12].copy_from_slice(&30000u32.to_be_bytes());
        buf[12..16].copy_from_slice(&1000u32.to_be_bytes());

        if let Some((prefix, prefix_len, valid, preferred, pio_flags)) = pio {
            buf.push(OPT_PREFIX_INFORMATION);
            buf.push(4); // 32 bytes / 8
            buf.push(prefix_len);
            buf.push(pio_flags);
            buf.extend_from_slice(&valid.to_be_bytes());
            buf.extend_from_slice(&preferred.to_be_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf.extend_from_slice(&prefix.octets());
        }
        buf
    }

    fn fixed_iid(_pio: &PrefixInformation) -> slaac::Iid {
        [0, 0, 0, 0, 0, 0, 0, 1]
    }

    #[tokio::test(start_paused = true)]
    async fn new_router_with_autonomous_prefix_configures_an_address() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 86400, 14400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();

        let now = Instant::now();
        let events = list.handle_ra(source, &ra, &raw, now, fixed_iid);

        let expected_addr = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(events.contains(&RaEvent::ConfigureAddress {
            address: expected_addr,
            prefix_len: 64,
            valid_secs: 86400,
            preferred_secs: 14400,
        }));
        assert!(events.contains(&RaEvent::Dhcp6(Dhcp6Trigger::None)));
        assert_eq!(list.routers().len(), 1);
        assert_eq!(list.routers()[0].prefixes.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn identical_ra_produces_no_events_but_still_refreshes_router_lifetime() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 86400, 14400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();

        let now = Instant::now();
        list.handle_ra(source, &ra, &raw, now, fixed_iid);

        tokio::time::advance(Duration::from_secs(60)).await;
        let now2 = Instant::now();
        let events = list.handle_ra(source, &ra, &raw, now2, fixed_iid);
        assert!(events.is_empty());
        // Router lifetime was refreshed relative to now2, not now.
        assert!(list.routers()[0].default_until.unwrap() > now + Duration::from_secs(1800));
    }

    #[tokio::test(start_paused = true)]
    async fn managed_flag_triggers_stateful_dhcp6() {
        let mut list = RouterList::new();
        let raw = sample_ra_bytes(0x80, 1800, None);
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        let events = list.handle_ra(Ipv6Addr::LOCALHOST, &ra, &raw, Instant::now(), fixed_iid);
        assert!(events.contains(&RaEvent::Dhcp6(Dhcp6Trigger::Stateful)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_ra_arriving_after_natural_expiry_removes_the_address_immediately() {
        // RFC4862 5.5.3.e never lets a single RA's valid=0 flash-expire a
        // prefix with a large remaining lifetime (covered at the pure-
        // function level by ipv6nd::tests::already_within_floor_ignores_
        // further_shortening and lifetime_over_two_hours_is_always_
        // applied_even_if_shorter_than_remaining) -- genuine removal via
        // merge_prefix (as opposed to the separate expire() sweep) only
        // happens once the prefix's own remaining lifetime has already
        // run out for real, at which point a follow-up RA's valid
        // lifetime (here 0, but any value would be) is used directly.
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw1 = sample_ra_bytes(0, 1800, Some((prefix, 64, 100, 100, 0xC0)));
        let ra1 = RouterAdvertisement::parse(&raw1).unwrap();
        list.handle_ra(source, &ra1, &raw1, Instant::now(), fixed_iid);

        tokio::time::advance(Duration::from_secs(200)).await;

        let raw2 = sample_ra_bytes(0, 1800, Some((prefix, 64, 0, 0, 0xC0)));
        let ra2 = RouterAdvertisement::parse(&raw2).unwrap();
        let events = list.handle_ra(source, &ra2, &raw2, Instant::now(), fixed_iid);

        let expected_addr = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(events.contains(&RaEvent::RemoveAddress { address: expected_addr }));
        assert!(list.routers()[0].prefixes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn expire_drops_addresses_past_their_valid_lifetime() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        // Short valid lifetime so the test doesn't wait long.
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 5, 5, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        let now = Instant::now();
        list.handle_ra(source, &ra, &raw, now, fixed_iid);

        tokio::time::advance(Duration::from_secs(10)).await;
        let events = list.expire(Instant::now());

        let expected_addr = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(events, vec![RaEvent::RemoveAddress { address: expected_addr }]);
        assert!(list.routers()[0].prefixes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn expire_drops_the_whole_router_once_lifetime_and_prefixes_are_both_gone() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let raw = sample_ra_bytes(0, 5, None); // 5s router lifetime, no prefixes
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);
        assert_eq!(list.routers().len(), 1);

        tokio::time::advance(Duration::from_secs(10)).await;
        list.expire(Instant::now());
        assert_eq!(list.routers().len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reserved_iid_skips_address_configuration() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 86400, 14400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();

        let events = list.handle_ra(source, &ra, &raw, Instant::now(), |_| [0u8; 8]); // subnet-router anycast, reserved
        assert!(!events.iter().any(|e| matches!(e, RaEvent::ConfigureAddress { .. })));
        assert!(list.routers()[0].prefixes[0].address.is_none());
    }
}
