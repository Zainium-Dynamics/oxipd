//! RFC 5227 ARP probe/announce/defend engine, shared by the DHCPv4 client
//! (duplicate-address detection on an offered lease) and IPv4LL (picking
//! and defending a 169.254.0.0/16 address). One [`ArpProbe`] per
//! (interface, candidate address) in flight.

use std::net::Ipv4Addr;
use std::time::Duration;

use oxipd_net::packet::{build_ethernet_frame, parse_ethernet_frame, RawSocket, BROADCAST_MAC, ETH_P_ARP};
use oxipd_proto::arp::{ArpPacket, MacAddr};
use rand::Rng;

/// RFC 5227 §1 timing constants, ported verbatim for interop parity.
pub const PROBE_WAIT: Duration = Duration::from_secs(1);
pub const PROBE_NUM: u32 = 3;
pub const PROBE_MIN: Duration = Duration::from_secs(1);
pub const PROBE_MAX: Duration = Duration::from_secs(2);
pub const ANNOUNCE_WAIT: Duration = Duration::from_secs(2);
pub const ANNOUNCE_NUM: u32 = 2;
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(2);
pub const MAX_CONFLICTS: u32 = 10;
pub const RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFEND_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Socket(#[from] oxipd_net::packet::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// No conflict observed for the whole RFC 5227 §2.1.1 probe sequence:
    /// the candidate address is free to claim.
    Available,
    /// Another host answered for, or is also probing, the candidate.
    Conflict,
}

/// RFC 5227 §2.1.1 conflict detection, as a pure function over one
/// observed ARP packet — unit-testable without any real socket.
///
/// `addr_is_configured` distinguishes the two conflict cases the RFC
/// defines: while still probing (not yet configured), *either* someone
/// answering for the candidate *or* someone else probing for the same
/// free address counts as a conflict; once the address is configured and
/// we're only defending it, only an actual claim (`sender_ip == addr`)
/// does.
pub fn detects_conflict(
    our_mac: MacAddr,
    probing_addr: Ipv4Addr,
    addr_is_configured: bool,
    frame_src_mac: MacAddr,
    pkt: &ArpPacket,
) -> bool {
    // Our own probes/announcements looped back (e.g. via a bridge).
    if frame_src_mac == our_mac {
        return false;
    }
    // Anti-spoof check (RFC 5227 §2.1.1): a packet's claimed ARP sender
    // hardware address must match the Ethernet frame's actual source.
    if pkt.sender_hw != frame_src_mac {
        return false;
    }

    if pkt.sender_ip == probing_addr {
        return true;
    }

    if !addr_is_configured && pkt.sender_ip.is_unspecified() && pkt.target_ip == probing_addr {
        // Another host probing for the same still-free address we want.
        return true;
    }

    false
}

fn jittered(min: Duration, max: Duration) -> Duration {
    let min_ms = min.as_millis() as u64;
    let max_ms = max.as_millis() as u64;
    let ms = rand::thread_rng().gen_range(min_ms..=max_ms);
    Duration::from_millis(ms)
}

/// Drives RFC 5227 probing/announcing/defending for one interface over a
/// dedicated ARP raw socket.
pub struct ArpProbe {
    socket: RawSocket,
    our_mac: MacAddr,
}

impl ArpProbe {
    pub fn new(socket: RawSocket, our_mac: MacAddr) -> Self {
        ArpProbe { socket, our_mac }
    }

    /// RFC 5227 §2.1.1: send `PROBE_NUM` probes with jittered spacing,
    /// then wait `ANNOUNCE_WAIT` for a reply, watching for a conflict the
    /// whole time.
    pub async fn probe(&self, addr: Ipv4Addr) -> Result<ProbeOutcome, Error> {
        for _ in 0..PROBE_NUM {
            self.send(&ArpPacket::probe(self.our_mac, addr)).await?;
            if self.listen(addr, false, Some(jittered(PROBE_MIN, PROBE_MAX))).await?.is_some() {
                return Ok(ProbeOutcome::Conflict);
            }
        }
        if self.listen(addr, false, Some(ANNOUNCE_WAIT)).await?.is_some() {
            return Ok(ProbeOutcome::Conflict);
        }
        Ok(ProbeOutcome::Available)
    }

    /// RFC 5227 §2.3: announce (gratuitous ARP) `ANNOUNCE_NUM` times,
    /// `ANNOUNCE_INTERVAL` apart.
    pub async fn announce(&self, addr: Ipv4Addr) -> Result<(), Error> {
        for i in 0..ANNOUNCE_NUM {
            self.send(&ArpPacket::announcement(self.our_mac, addr)).await?;
            if i + 1 < ANNOUNCE_NUM {
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        }
        Ok(())
    }

    /// Block until a conflict is observed on an already-configured
    /// address, then attempt to defend it once (RFC 5227 §2.4). Returns
    /// `true` if the defense was rate-limited and the address should be
    /// given up, `false` if we successfully (re-)announced and should
    /// keep watching.
    ///
    /// `last_defend` should be threaded across calls by the caller (it's
    /// per-address state, not per-probe-socket state).
    pub async fn watch_once(
        &self,
        addr: Ipv4Addr,
        last_defend: Option<tokio::time::Instant>,
        persist_defence: bool,
    ) -> Result<WatchResult, Error> {
        if self.listen(addr, true, None).await?.is_none() {
            // `listen` with no timeout only returns `None` if the socket
            // was closed out from under us; nothing left to watch.
            return Ok(WatchResult::SocketClosed);
        }

        let now = tokio::time::Instant::now();
        let rate_limited = last_defend.is_some_and(|t| now.duration_since(t) < DEFEND_INTERVAL);
        if rate_limited && !persist_defence {
            return Ok(WatchResult::GiveUp);
        }
        self.announce(addr).await?;
        Ok(WatchResult::Defended { at: now })
    }

    async fn send(&self, pkt: &ArpPacket) -> Result<(), Error> {
        let frame = build_ethernet_frame(BROADCAST_MAC, self.our_mac, ETH_P_ARP, &pkt.build());
        self.socket.send_frame(&frame).await?;
        Ok(())
    }

    /// Wait up to `timeout` (or indefinitely if `None`) for a conflicting
    /// ARP packet. Returns the offending packet, or `None` on timeout.
    async fn listen(
        &self,
        addr: Ipv4Addr,
        configured: bool,
        timeout: Option<Duration>,
    ) -> Result<Option<ArpPacket>, Error> {
        let mut buf = vec![0u8; 128];
        let recv_one = async {
            loop {
                let n = self.socket.recv_frame(&mut buf).await?;
                let Some(frame) = parse_ethernet_frame(&buf[..n]) else {
                    continue;
                };
                let Some(pkt) = ArpPacket::parse(frame.payload) else {
                    continue;
                };
                if detects_conflict(self.our_mac, addr, configured, frame.src, &pkt) {
                    return Ok::<_, Error>(Some(pkt));
                }
            }
        };

        match timeout {
            None => recv_one.await,
            Some(d) => match tokio::time::timeout(d, recv_one).await {
                Ok(result) => result,
                Err(_elapsed) => Ok(None),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchResult {
    /// Re-announced successfully; caller should record `at` as the new
    /// last-defend time and keep watching.
    Defended { at: tokio::time::Instant },
    /// Rate-limited (defended within [`DEFEND_INTERVAL`]) and not in
    /// persistent-defence mode: caller should drop the address.
    GiveUp,
    /// The underlying socket is gone; nothing more to watch.
    SocketClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        [0x02, 0, 0, 0, 0, n]
    }

    #[test]
    fn own_reflected_frame_is_not_a_conflict() {
        let us = mac(1);
        let addr = Ipv4Addr::new(169, 254, 1, 1);
        let pkt = ArpPacket::announcement(us, addr);
        assert!(!detects_conflict(us, addr, true, us, &pkt));
    }

    #[test]
    fn spoofed_sender_hardware_is_ignored() {
        let us = mac(1);
        let other = mac(2);
        let attacker_frame_src = mac(3);
        let addr = Ipv4Addr::new(169, 254, 1, 1);
        // Packet claims sender_hw = `other`, but the frame actually came
        // from `attacker_frame_src` — mismatch, must be ignored.
        let pkt = ArpPacket {
            operation: oxipd_proto::arp::OP_REQUEST,
            sender_hw: other,
            sender_ip: addr,
            target_hw: [0; 6],
            target_ip: addr,
        };
        assert!(!detects_conflict(us, addr, true, attacker_frame_src, &pkt));
    }

    #[test]
    fn someone_else_claiming_our_address_is_a_conflict_whether_or_not_configured() {
        let us = mac(1);
        let other = mac(2);
        let addr = Ipv4Addr::new(169, 254, 1, 1);
        let pkt = ArpPacket::announcement(other, addr);
        assert!(detects_conflict(us, addr, true, other, &pkt));
        assert!(detects_conflict(us, addr, false, other, &pkt));
    }

    #[test]
    fn rival_probe_for_same_free_address_is_only_a_conflict_pre_configuration() {
        let us = mac(1);
        let other = mac(2);
        let addr = Ipv4Addr::new(169, 254, 1, 1);
        let pkt = ArpPacket::probe(other, addr);
        assert!(detects_conflict(us, addr, false, other, &pkt));
        // Once we already hold the address, a rival merely probing for it
        // (sender_ip unspecified) isn't a claim on our address yet.
        assert!(!detects_conflict(us, addr, true, other, &pkt));
    }

    #[test]
    fn unrelated_traffic_is_not_a_conflict() {
        let us = mac(1);
        let other = mac(2);
        let addr = Ipv4Addr::new(169, 254, 1, 1);
        let unrelated = ArpPacket::announcement(other, Ipv4Addr::new(169, 254, 9, 9));
        assert!(!detects_conflict(us, addr, true, other, &unrelated));
    }
}
