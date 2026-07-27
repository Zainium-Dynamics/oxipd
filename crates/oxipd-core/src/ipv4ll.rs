//! RFC 3927 IPv4 Link-Local (APIPA) address selection. Reuses
//! [`crate::arp::ArpProbe`] for duplicate-address detection — this module
//! only owns the "which address, and when to retry" policy.

use std::net::Ipv4Addr;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::arp::{ArpProbe, ProbeOutcome, MAX_CONFLICTS, PROBE_WAIT, RATE_LIMIT_INTERVAL};

/// RFC 3927 §2.1: usable range is 169.254.1.0-169.254.254.255 (the
/// first and last /24 of 169.254.0.0/16 are reserved).
pub const NETWORK: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 0);
pub const PREFIX_LEN: u8 = 16;
const HOST_MIN: u32 = 0x0100; // 169.254.1.0
const HOST_MAX: u32 = 0xfeff; // 169.254.254.255

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Arp(#[from] crate::arp::Error),
}

/// Deterministically derive a candidate address from the interface's MAC
/// and a retry counter. RFC 3927 §2.1 motivates seeding from the hardware
/// address so a host without persistent storage tends to reclaim the same
/// address across reboots; this doesn't need to bit-match any particular
/// other implementation's sequence, only that policy.
pub fn pick_addr(mac: &[u8; 6], attempt: u32) -> Ipv4Addr {
    let seed = seed_from_mac(mac, attempt);
    let mut rng = StdRng::seed_from_u64(seed);
    let host: u32 = rng.gen_range(HOST_MIN..=HOST_MAX);
    Ipv4Addr::from((169u32 << 24) | (254u32 << 16) | host)
}

fn seed_from_mac(mac: &[u8; 6], attempt: u32) -> u64 {
    // FNV-1a: simple, deterministic, and dependency-free.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in mac.iter().chain(attempt.to_be_bytes().iter()) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// RFC 3927 §2.2.1: pick a candidate, ARP-probe it (via `probe`), and on
/// conflict retry with a fresh candidate — rate-limited to once per
/// [`RATE_LIMIT_INTERVAL`] after [`MAX_CONFLICTS`] consecutive failures,
/// otherwise retrying after [`PROBE_WAIT`]. Only returns `Err` on a real
/// socket failure; conflicts are retried forever.
///
/// On success the caller is responsible for configuring the address on
/// the interface and then calling `probe.announce(addr)` (this module
/// only owns address *selection*, not installation, since installing an
/// address is a netlink concern that belongs to the caller's interface
/// manager).
pub async fn acquire(probe: &ArpProbe, mac: [u8; 6]) -> Result<Ipv4Addr, Error> {
    let mut attempt = 0u32;
    let mut conflicts = 0u32;
    loop {
        let candidate = pick_addr(&mac, attempt);
        match probe.probe(candidate).await? {
            ProbeOutcome::Available => return Ok(candidate),
            ProbeOutcome::Conflict => {
                conflicts += 1;
                attempt += 1;
                let backoff = if conflicts >= MAX_CONFLICTS {
                    RATE_LIMIT_INTERVAL
                } else {
                    PROBE_WAIT
                };
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Sanity bound used only by tests/callers that want to assert an address
/// really is in the link-local range (e.g. after loading one back from a
/// persisted lease file).
pub fn is_valid_linklocal(addr: Ipv4Addr) -> bool {
    let bits = u32::from(addr);
    let host = bits & 0xffff;
    (bits >> 16) == 0xa9fe && (HOST_MIN..=HOST_MAX).contains(&host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picked_addresses_are_always_in_the_valid_range() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        for attempt in 0..500 {
            let addr = pick_addr(&mac, attempt);
            assert!(
                is_valid_linklocal(addr),
                "attempt {attempt} produced out-of-range address {addr}"
            );
        }
    }

    #[test]
    fn same_mac_and_attempt_is_deterministic() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(pick_addr(&mac, 3), pick_addr(&mac, 3));
    }

    #[test]
    fn different_attempts_usually_differ() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let addrs: std::collections::HashSet<_> = (0..16).map(|a| pick_addr(&mac, a)).collect();
        assert!(addrs.len() > 1, "16 attempts all produced the same address");
    }

    #[test]
    fn different_macs_usually_differ() {
        let a = pick_addr(&[0x02, 0, 0, 0, 0, 1], 0);
        let b = pick_addr(&[0x02, 0, 0, 0, 0, 2], 0);
        assert_ne!(a, b);
    }

    #[test]
    fn reserved_subnets_are_rejected_by_the_validity_check() {
        assert!(!is_valid_linklocal(Ipv4Addr::new(169, 254, 0, 5)));
        assert!(!is_valid_linklocal(Ipv4Addr::new(169, 254, 255, 5)));
        assert!(!is_valid_linklocal(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_valid_linklocal(Ipv4Addr::new(169, 254, 1, 0)));
        assert!(is_valid_linklocal(Ipv4Addr::new(169, 254, 254, 255)));
    }
}
