//! Retransmission/backoff/T1-T2 timing, ported from dhcpcd's constants
//! (deliberately not the literal RFC 2131 §4.1 algorithm — dhcpcd's own
//! simplification is kept for interop parity, per PLAN.md).

use std::time::Duration;

use rand::Rng;

/// First retransmit delay; doubles on each subsequent retransmit up to
/// [`RETRANSMIT_MAX`].
pub const RETRANSMIT_BASE: Duration = Duration::from_secs(4);
pub const RETRANSMIT_MAX: Duration = Duration::from_secs(64);
/// Applied as ± this many milliseconds on every retransmit delay.
pub const RETRANSMIT_JITTER_MS: i64 = 1000;

/// Separate exponential backoff for repeated NAKs, distinct from the
/// per-phase retransmit backoff above.
pub const NAK_BACKOFF_BASE: Duration = Duration::from_secs(1);
pub const NAK_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// RFC 2131 doesn't set a minimum, but a near-zero lease is almost always
/// a misconfigured server; dhcpcd clamps to this floor.
pub const MIN_LEASE_SECS: u32 = 20;

/// Watchdog for "no reply at all" while in SELECTING/INIT-REBOOT, separate
/// from the retransmit timer.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

const T1_FACTOR: f64 = 0.5;
const T2_FACTOR: f64 = 0.875;

/// `interval` -> `min(interval * 2, RETRANSMIT_MAX)`, or `RETRANSMIT_BASE`
/// for the first send of a phase (`prev == None`).
pub fn next_retransmit_interval(prev: Option<Duration>) -> Duration {
    match prev {
        None => RETRANSMIT_BASE,
        Some(p) => p.saturating_mul(2).min(RETRANSMIT_MAX),
    }
}

/// Same shape as [`next_retransmit_interval`], for the NAK counter.
pub fn next_nak_backoff(prev: Option<Duration>) -> Duration {
    match prev {
        None => NAK_BACKOFF_BASE,
        Some(p) => p.saturating_mul(2).min(NAK_BACKOFF_MAX),
    }
}

/// Apply dhcpcd's ±1s jitter to a retransmit interval. Never returns a
/// negative delay (clamped to zero).
pub fn jittered(interval: Duration) -> Duration {
    let jitter_ms = rand::thread_rng().gen_range(-RETRANSMIT_JITTER_MS..=RETRANSMIT_JITTER_MS);
    let total_ms = interval.as_millis() as i64 + jitter_ms;
    Duration::from_millis(total_ms.max(0) as u64)
}

/// RFC 2131 §4.4.5 T1/T2 computation: use the server-supplied values
/// (options 58/59) if present and sane (`t1 <= t2 < lease_time`),
/// otherwise fall back to the 0.5/0.875 defaults. An infinite lease
/// (`u32::MAX`) has no renewal/rebinding timers at all.
pub fn compute_t1_t2(lease_time: u32, server_t1: Option<u32>, server_t2: Option<u32>) -> (u32, u32) {
    if lease_time == u32::MAX {
        return (u32::MAX, u32::MAX);
    }
    let default_t1 = (lease_time as f64 * T1_FACTOR) as u32;
    let default_t2 = (lease_time as f64 * T2_FACTOR) as u32;

    let t1 = server_t1.unwrap_or(default_t1);
    let t2 = server_t2.unwrap_or(default_t2);
    if t1 > t2 || t2 >= lease_time {
        (default_t1, default_t2)
    } else {
        (t1, t2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retransmit_doubles_then_caps() {
        let mut d = None;
        let expected = [4, 8, 16, 32, 64, 64, 64];
        for &secs in &expected {
            let next = next_retransmit_interval(d);
            assert_eq!(next, Duration::from_secs(secs));
            d = Some(next);
        }
    }

    #[test]
    fn nak_backoff_doubles_then_caps_at_60() {
        let mut d = None;
        let expected = [1, 2, 4, 8, 16, 32, 60, 60];
        for &secs in &expected {
            let next = next_nak_backoff(d);
            assert_eq!(next, Duration::from_secs(secs));
            d = Some(next);
        }
    }

    #[test]
    fn jitter_stays_within_one_second_and_never_negative() {
        for _ in 0..200 {
            let j = jittered(Duration::from_secs(4));
            assert!(j >= Duration::from_secs(3));
            assert!(j <= Duration::from_secs(5));
        }
        // A tiny interval must still clamp to zero, not underflow/panic.
        for _ in 0..200 {
            let j = jittered(Duration::from_millis(10));
            assert!(j <= Duration::from_millis(1010));
        }
    }

    #[test]
    fn t1_t2_default_to_half_and_seven_eighths() {
        let (t1, t2) = compute_t1_t2(1000, None, None);
        assert_eq!(t1, 500);
        assert_eq!(t2, 875);
    }

    #[test]
    fn t1_t2_honors_sane_server_values() {
        let (t1, t2) = compute_t1_t2(1000, Some(400), Some(900));
        assert_eq!((t1, t2), (400, 900));
    }

    #[test]
    fn t1_t2_falls_back_when_server_values_are_nonsensical() {
        // t2 >= lease_time is invalid.
        let (t1, t2) = compute_t1_t2(1000, Some(400), Some(1000));
        assert_eq!((t1, t2), (500, 875));
        // t1 > t2 is invalid.
        let (t1, t2) = compute_t1_t2(1000, Some(900), Some(400));
        assert_eq!((t1, t2), (500, 875));
    }

    #[test]
    fn infinite_lease_has_no_renew_rebind_timers() {
        assert_eq!(compute_t1_t2(u32::MAX, None, None), (u32::MAX, u32::MAX));
    }
}
