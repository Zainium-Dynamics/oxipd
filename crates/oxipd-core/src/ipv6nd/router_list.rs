//! The stateful half of RA processing: tracks every router/prefix
//! currently known (mirroring dhcpcd's `ctx->ra_routers` + per-router
//! `rap->addrs`), building on the pure policy functions in the parent
//! module (`dhcp6_trigger`, `effective_valid_lifetime`, `ra_changed`).
//!
//! An RA's full prefix list is merged in (RFC 4862 §5.5.3's add/extend/
//! deprecate semantics), but a prefix that simply stops being mentioned in
//! a later, otherwise-changed RA is not implicitly withdrawn: only an
//! explicit valid-lifetime-zero PIO or the router's own lifetime elapsing
//! removes anything. Real routers re-advertise every active prefix, so
//! this is fine in practice.

use std::net::Ipv6Addr;
use std::time::Duration;

use oxipd_proto::ndp::{PrefixInformation, RouterAdvertisement, OPT_PREFIX_INFORMATION};
use rand::Rng;
use tokio::time::Instant;

use crate::ipv6::slaac;

use super::{dhcp6_trigger, effective_valid_lifetime, ra_changed, Dhcp6Trigger};

/// RFC 8981 limits for temporary addresses.
const TEMP_VALID_MAX_SECS: u32 = 7 * 86400;
const TEMP_PREFERRED_MAX_SECS: u32 = 86400;
const TEMP_DESYNC_MAX_SECS: u32 = 600;

/// How many times a failed-DAD address is regenerated (RFC 7217 §6 says
/// at least 3 tries) before giving up on that prefix.
pub const MAX_DAD_RETRIES: u8 = 3;

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
    /// RFC 8981 temporary address for this prefix, if enabled.
    pub temp_address: Option<Ipv6Addr>,
    temp_preferred_until: Option<Instant>,
    dad_counter: u8,
}

impl Prefix {
    fn remaining_valid_secs(&self, now: Instant) -> Option<u32> {
        (self.valid_until > now).then(|| (self.valid_until - now).as_secs() as u32)
    }

    fn remaining_preferred_secs(&self, now: Instant) -> u32 {
        self.preferred_until
            .saturating_duration_since(now)
            .as_secs() as u32
    }

    fn removal_events(&self) -> impl Iterator<Item = RaEvent> {
        let prefix_len = self.prefix_len;
        [self.address, self.temp_address]
            .into_iter()
            .flatten()
            .map(move |address| RaEvent::RemoveAddress {
                address,
                prefix_len,
            })
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

/// What the async shell should do in response to processing a Router
/// Advertisement, an expiry sweep, or a DAD failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaEvent {
    /// Configure (or re-affirm, with updated lifetimes) a SLAAC address.
    ConfigureAddress {
        address: Ipv6Addr,
        prefix_len: u8,
        valid_secs: u32,
        preferred_secs: u32,
    },
    /// A previously configured address should be removed from the
    /// interface (its prefix expired, or it failed DAD).
    RemoveAddress { address: Ipv6Addr, prefix_len: u8 },
    /// Install a default route via this router's link-local address.
    AddDefaultRoute { gateway: Ipv6Addr },
    /// The router stopped being a default router (lifetime 0 or expired).
    RemoveDefaultRoute { gateway: Ipv6Addr },
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
    temp_addresses: bool,
}

impl RouterList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Also generate an RFC 8981 temporary address for each autonomous
    /// prefix.
    pub fn with_temporary_addresses(mut self, enabled: bool) -> Self {
        self.temp_addresses = enabled;
        self
    }

    pub fn routers(&self) -> &[Router] {
        &self.routers
    }

    /// Process one received RA. `make_iid(pio, dad_counter)` generates the
    /// SLAAC interface identifier for an autonomous prefix: the caller
    /// supplies it since it needs interface-specific state (MAC for
    /// EUI-64, or the RFC 7217 secret) this module doesn't own.
    pub fn handle_ra(
        &mut self,
        source: Ipv6Addr,
        ra: &RouterAdvertisement,
        raw: &[u8],
        now: Instant,
        make_iid: impl Fn(&PrefixInformation, u8) -> slaac::Iid,
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

        let was_default = self.routers[idx].default_until.is_some_and(|t| t > now);
        let default_until = router_lifetime_until(ra, now);
        let mut events = Vec::new();
        match (was_default, default_until.is_some()) {
            (false, true) => events.push(RaEvent::AddDefaultRoute { gateway: source }),
            (true, false) => events.push(RaEvent::RemoveDefaultRoute { gateway: source }),
            _ => {}
        }

        // Routers re-send periodically even with nothing new to say;
        // still refresh this router's own lifetime, but skip re-deriving
        // prefix/DHCPv6 events for byte-identical content.
        if !ra_changed(Some(&self.routers[idx].last_data), raw) {
            self.routers[idx].default_until = default_until;
            return events;
        }

        self.routers[idx].last_data = raw.to_vec();
        self.routers[idx].managed = ra.managed();
        self.routers[idx].other_config = ra.other_config();
        self.routers[idx].default_until = default_until;

        events.push(RaEvent::ApplyLinkParameters {
            hop_limit: ra.cur_hop_limit(),
            reachable_time_ms: ra.reachable_time_ms(),
            retrans_timer_ms: ra.retrans_timer_ms(),
        });
        events.push(RaEvent::Dhcp6(dhcp6_trigger(
            ra.managed(),
            ra.other_config(),
        )));

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
        make_iid: &impl Fn(&PrefixInformation, u8) -> slaac::Iid,
    ) -> Vec<RaEvent> {
        let temp_enabled = self.temp_addresses;
        let router = &mut self.routers[router_idx];
        let existing_idx = router
            .prefixes
            .iter()
            .position(|p| p.prefix == pio.prefix && p.prefix_len == pio.prefix_len);

        let remaining = existing_idx.and_then(|i| router.prefixes[i].remaining_valid_secs(now));
        let valid_secs = effective_valid_lifetime(remaining, pio.valid_lifetime_secs);

        if valid_secs == 0 {
            return match existing_idx {
                Some(i) => router.prefixes.remove(i).removal_events().collect(),
                None => Vec::new(),
            };
        }

        let valid_until = now + Duration::from_secs(valid_secs as u64);
        let preferred_secs = pio.preferred_lifetime_secs.min(valid_secs);
        let preferred_until = now + Duration::from_secs(preferred_secs as u64);

        let (mut temp_address, mut temp_preferred_until, dad_counter) = match existing_idx {
            Some(i) => {
                let p = &router.prefixes[i];
                (p.temp_address, p.temp_preferred_until, p.dad_counter)
            }
            None => (None, None, 0),
        };

        let mut events = Vec::new();

        let address = if pio.autonomous {
            let iid = make_iid(pio, dad_counter);
            (!slaac::is_reserved_iid(&iid)).then(|| slaac::make_address(pio.prefix, iid))
        } else {
            None
        };
        if let Some(address) = address {
            events.push(RaEvent::ConfigureAddress {
                address,
                prefix_len: pio.prefix_len,
                valid_secs,
                preferred_secs,
            });
        }

        // A new temporary address is made when there is none yet, or the
        // current one has stopped being preferred (RFC 8981 §3.4).
        if temp_enabled && pio.autonomous && temp_preferred_until.is_none_or(|t| t <= now) {
            let desync = rand::thread_rng().gen_range(0..=TEMP_DESYNC_MAX_SECS);
            let temp_valid = valid_secs.min(TEMP_VALID_MAX_SECS);
            let temp_preferred = preferred_secs
                .min(TEMP_PREFERRED_MAX_SECS - desync)
                .min(temp_valid);
            if temp_preferred > 0 {
                let addr = slaac::make_address(pio.prefix, slaac::temporary_iid());
                events.push(RaEvent::ConfigureAddress {
                    address: addr,
                    prefix_len: pio.prefix_len,
                    valid_secs: temp_valid,
                    preferred_secs: temp_preferred,
                });
                temp_address = Some(addr);
                temp_preferred_until = Some(now + Duration::from_secs(temp_preferred as u64));
            }
        }

        let new_prefix = Prefix {
            prefix: pio.prefix,
            prefix_len: pio.prefix_len,
            on_link: pio.on_link,
            autonomous: pio.autonomous,
            valid_until,
            preferred_until,
            address,
            temp_address,
            temp_preferred_until,
            dad_counter,
        };
        match existing_idx {
            Some(i) => router.prefixes[i] = new_prefix,
            None => router.prefixes.push(new_prefix),
        }

        events
    }

    /// The kernel reported DAD failure for `address`. Drop it and, if the
    /// interface identifier scheme can produce a different one (RFC 7217
    /// with a bumped counter), configure a replacement. Returns nothing
    /// for addresses we don't own.
    pub fn handle_dad_failure(
        &mut self,
        address: Ipv6Addr,
        now: Instant,
        make_iid: impl Fn(&PrefixInformation, u8) -> slaac::Iid,
    ) -> Vec<RaEvent> {
        for router in &mut self.routers {
            let Some(prefix) = router
                .prefixes
                .iter_mut()
                .find(|p| p.address == Some(address))
            else {
                continue;
            };
            let mut events = vec![RaEvent::RemoveAddress {
                address,
                prefix_len: prefix.prefix_len,
            }];
            prefix.address = None;
            if prefix.dad_counter >= MAX_DAD_RETRIES {
                tracing::warn!(%address, "ipv6nd: DAD kept failing, giving up on this prefix");
                return events;
            }
            let pio = PrefixInformation {
                prefix: prefix.prefix,
                prefix_len: prefix.prefix_len,
                on_link: prefix.on_link,
                autonomous: prefix.autonomous,
                valid_lifetime_secs: 0,
                preferred_lifetime_secs: 0,
            };
            let next_counter = prefix.dad_counter + 1;
            let iid = make_iid(&pio, next_counter);
            let new_addr = slaac::make_address(prefix.prefix, iid);
            // Schemes that ignore the counter (EUI-64) would just collide again.
            if new_addr == address || slaac::is_reserved_iid(&iid) {
                tracing::warn!(%address, "ipv6nd: DAD failed and this scheme has no alternative address");
                return events;
            }
            prefix.dad_counter = next_counter;
            prefix.address = Some(new_addr);
            events.push(RaEvent::ConfigureAddress {
                address: new_addr,
                prefix_len: prefix.prefix_len,
                valid_secs: prefix.remaining_valid_secs(now).unwrap_or(0),
                preferred_secs: prefix.remaining_preferred_secs(now),
            });
            return events;
        }
        Vec::new()
    }

    /// Sweep for prefixes/routers whose lifetime has elapsed. Call
    /// periodically (e.g. driven by whichever known expiry is soonest).
    pub fn expire(&mut self, now: Instant) -> Vec<RaEvent> {
        let mut events = Vec::new();
        self.routers.retain_mut(|router| {
            if router.default_until.is_some_and(|t| t <= now) {
                router.default_until = None;
                events.push(RaEvent::RemoveDefaultRoute {
                    gateway: router.source,
                });
            }
            router.prefixes.retain(|p| {
                if p.valid_until > now {
                    return true;
                }
                events.extend(p.removal_events());
                false
            });
            router.default_until.is_some() || !router.prefixes.is_empty()
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

    fn sample_ra_bytes(
        flags: u8,
        router_lifetime: u16,
        pio: Option<(Ipv6Addr, u8, u32, u32, u8)>,
    ) -> Vec<u8> {
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

    fn fixed_iid(_pio: &PrefixInformation, _dad: u8) -> slaac::Iid {
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
        assert!(events.contains(&RaEvent::RemoveAddress {
            address: expected_addr,
            prefix_len: 64
        }));
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
        assert_eq!(
            events,
            vec![RaEvent::RemoveAddress {
                address: expected_addr,
                prefix_len: 64
            }]
        );
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

        let events = list.handle_ra(source, &ra, &raw, Instant::now(), |_, _| [0u8; 8]); // subnet-router anycast, reserved
        assert!(!events
            .iter()
            .any(|e| matches!(e, RaEvent::ConfigureAddress { .. })));
        assert!(list.routers()[0].prefixes[0].address.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn router_with_lifetime_gets_a_default_route_once() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let raw = sample_ra_bytes(0, 1800, None);
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        let events = list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);
        assert!(events.contains(&RaEvent::AddDefaultRoute { gateway: source }));

        let events = list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);
        assert!(events.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn router_lifetime_zero_withdraws_the_default_route() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let raw = sample_ra_bytes(0, 1800, None);
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);

        let raw = sample_ra_bytes(0, 0, None);
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        let events = list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);
        assert!(events.contains(&RaEvent::RemoveDefaultRoute { gateway: source }));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_withdraws_the_default_route() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let raw = sample_ra_bytes(0, 5, None);
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);

        tokio::time::advance(Duration::from_secs(10)).await;
        let events = list.expire(Instant::now());
        assert_eq!(
            events,
            vec![RaEvent::RemoveDefaultRoute { gateway: source }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn temporary_address_is_added_alongside_the_stable_one() {
        let mut list = RouterList::new().with_temporary_addresses(true);
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 30 * 86400, 7 * 86400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        let events = list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);

        let configured: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RaEvent::ConfigureAddress {
                    address,
                    valid_secs,
                    preferred_secs,
                    ..
                } => Some((*address, *valid_secs, *preferred_secs)),
                _ => None,
            })
            .collect();
        assert_eq!(configured.len(), 2);
        let (temp, valid, preferred) = configured[1];
        assert_eq!(list.routers()[0].prefixes[0].temp_address, Some(temp));
        assert_eq!(valid, TEMP_VALID_MAX_SECS);
        assert!(preferred <= TEMP_PREFERRED_MAX_SECS);
    }

    #[tokio::test(start_paused = true)]
    async fn dad_failure_retries_with_a_new_iid_when_the_scheme_allows() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 86400, 14400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        // IID depends on the DAD counter, like RFC 7217.
        let by_counter = |_: &PrefixInformation, dad: u8| [0, 0, 0, 0, 0, 0, 0, dad + 1];
        list.handle_ra(source, &ra, &raw, Instant::now(), by_counter);

        let first = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 1]);
        let second = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 2]);
        let events = list.handle_dad_failure(first, Instant::now(), by_counter);
        assert!(events.contains(&RaEvent::RemoveAddress {
            address: first,
            prefix_len: 64
        }));
        assert!(events
            .iter()
            .any(|e| matches!(e, RaEvent::ConfigureAddress { address, .. } if *address == second)));
        assert_eq!(list.routers()[0].prefixes[0].address, Some(second));
    }

    #[tokio::test(start_paused = true)]
    async fn dad_failure_with_a_counter_blind_scheme_just_removes_the_address() {
        let mut list = RouterList::new();
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let raw = sample_ra_bytes(0, 1800, Some((prefix, 64, 86400, 14400, 0xC0)));
        let ra = RouterAdvertisement::parse(&raw).unwrap();
        list.handle_ra(source, &ra, &raw, Instant::now(), fixed_iid);

        let addr = slaac::make_address(prefix, [0, 0, 0, 0, 0, 0, 0, 1]);
        let events = list.handle_dad_failure(addr, Instant::now(), fixed_iid);
        assert_eq!(
            events,
            vec![RaEvent::RemoveAddress {
                address: addr,
                prefix_len: 64
            }]
        );
        assert!(list.routers()[0].prefixes[0].address.is_none());
    }
}
