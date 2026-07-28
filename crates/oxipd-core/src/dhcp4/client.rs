//! The async "shell" that drives [`Dhcp4Fsm`] over real sockets and
//! netlink: the only impure part of the DHCPv4 client, everything else
//! (protocol logic, timing, message codec) lives in the pure modules this
//! wires together. Not unit tested (it needs a real raw socket, which
//! needs `CAP_NET_RAW`) — exercised instead by a network-namespace
//! integration test against a real DHCP server (see PLAN.md's M3
//! milestone verification step).
//!
//! Callers are responsible for actually opening the raw sockets (directly,
//! or via `oxipd_privsep`) and handing them to [`Dhcp4Client::new`]; this
//! module doesn't know or care which.

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;

use oxipd_net::netlink::NetlinkClient;
use oxipd_net::packet::{RawSocket, BROADCAST_MAC};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::fsm::{Action, Dhcp4Fsm, Event};
use super::lease::Lease;
use super::raw_frame::{self, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use super::message;
use crate::arp::{ArpProbe, ProbeOutcome};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Packet(#[from] oxipd_net::packet::Error),
    #[error(transparent)]
    Netlink(#[from] oxipd_net::netlink::Error),
    #[error(transparent)]
    Arp(#[from] crate::arp::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerKind {
    Retransmit,
    RequestTimeout,
    Renew,
    Rebind,
    Expire,
    NakBackoff,
}

impl TimerKind {
    fn to_event(self) -> Event {
        match self {
            TimerKind::Retransmit => Event::RetransmitTimeout,
            TimerKind::RequestTimeout => Event::RequestTimeoutExpired,
            TimerKind::Renew => Event::RenewTimerFired,
            TimerKind::Rebind => Event::RebindTimerFired,
            TimerKind::Expire => Event::LeaseExpired,
            TimerKind::NakBackoff => Event::NakBackoffElapsed,
        }
    }
}

/// One deadline per concern, rather than dhcpcd's sorted-timer-list +
/// queue-tag cancellation — `CancelAllTimers` just clears every field.
#[derive(Default)]
struct Timers {
    retransmit: Option<Instant>,
    request_timeout: Option<Instant>,
    renew: Option<Instant>,
    rebind: Option<Instant>,
    expire: Option<Instant>,
    nak_backoff: Option<Instant>,
}

impl Timers {
    fn earliest(&self) -> Option<(TimerKind, Instant)> {
        [
            (TimerKind::Retransmit, self.retransmit),
            (TimerKind::RequestTimeout, self.request_timeout),
            (TimerKind::Renew, self.renew),
            (TimerKind::Rebind, self.rebind),
            (TimerKind::Expire, self.expire),
            (TimerKind::NakBackoff, self.nak_backoff),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|d| (k, d)))
        .min_by_key(|(_, d)| *d)
    }

    fn clear_all(&mut self) {
        *self = Timers::default();
    }

    fn clear(&mut self, kind: TimerKind) {
        self.slot(kind).take();
    }

    fn arm(&mut self, kind: TimerKind, deadline: Instant) {
        *self.slot(kind) = Some(deadline);
    }

    fn slot(&mut self, kind: TimerKind) -> &mut Option<Instant> {
        match kind {
            TimerKind::Retransmit => &mut self.retransmit,
            TimerKind::RequestTimeout => &mut self.request_timeout,
            TimerKind::Renew => &mut self.renew,
            TimerKind::Rebind => &mut self.rebind,
            TimerKind::Expire => &mut self.expire,
            TimerKind::NakBackoff => &mut self.nak_backoff,
        }
    }
}

/// Drives one interface's DHCPv4 acquisition/renewal lifecycle.
pub struct Dhcp4Client {
    fsm: Dhcp4Fsm,
    mac: [u8; 6],
    ifindex: u32,
    phase_started_at: Instant,
    /// Pre-bind transport (broadcast-capable raw socket); `None` once
    /// [`Self::on_bound`] has swapped over to `udp`.
    raw: Option<RawSocket>,
    /// Post-bind transport; present from the first successful bind
    /// onward (renew/rebind/re-bind all reuse it).
    udp: Option<UdpSocket>,
    arp: ArpProbe,
    netlink: NetlinkClient,
    timers: Timers,
}

impl Dhcp4Client {
    pub fn new(mac: [u8; 6], ifindex: u32, raw: RawSocket, arp_socket: RawSocket, netlink: NetlinkClient) -> Self {
        Dhcp4Client {
            fsm: Dhcp4Fsm::new(),
            mac,
            ifindex,
            phase_started_at: Instant::now(),
            raw: Some(raw),
            udp: None,
            arp: ArpProbe::new(arp_socket, mac),
            netlink,
            timers: Timers::default(),
        }
    }

    pub fn fsm(&self) -> &Dhcp4Fsm {
        &self.fsm
    }

    /// Feed `initial` (typically [`Event::Start`] or
    /// [`Event::StartReboot`]) and then run the client's event loop
    /// forever, driving retransmits/T1/T2/expiry timers and incoming
    /// packets into the state machine. Returns only on a real I/O error.
    pub async fn run(&mut self, initial: Event) -> Result<(), Error> {
        self.dispatch(initial).await?;
        loop {
            let due = self.timers.earliest();
            tokio::select! {
                maybe_event = self.recv_event() => {
                    if let Some(event) = maybe_event? {
                        self.dispatch(event).await?;
                    }
                }
                _ = Self::timer_future(due) => {
                    if let Some((kind, _)) = due {
                        self.timers.clear(kind);
                        self.dispatch(kind.to_event()).await?;
                    }
                }
            }
        }
    }

    async fn timer_future(due: Option<(TimerKind, Instant)>) {
        match due {
            Some((_, deadline)) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }

    fn secs(&self) -> u16 {
        self.phase_started_at.elapsed().as_secs().min(u16::MAX as u64) as u16
    }

    async fn dispatch(&mut self, event: Event) -> Result<(), Error> {
        if matches!(
            event,
            Event::Start | Event::StartReboot(_) | Event::NakBackoffElapsed | Event::LeaseExpired | Event::ProbeConflict
        ) {
            self.phase_started_at = Instant::now();
        }
        let actions = self.fsm.handle(event);
        self.execute(actions).await
    }

    /// Boxed rather than a plain `async fn` because [`Action::StartArpProbe`]
    /// needs to recurse back into [`Self::dispatch`] (which calls this),
    /// and a self-recursive `async fn` has no statically-known size.
    fn execute(&mut self, actions: Vec<Action>) -> Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + '_>> {
        Box::pin(async move {
            for action in actions {
                match action {
                    Action::SendDiscover => {
                        let bytes = message::build_discover(self.mac, self.fsm.xid(), self.secs(), None);
                        self.send_broadcast(bytes).await?;
                    }
                    Action::SendRequest {
                        requested_addr,
                        server_id,
                        unicast_to,
                    } => {
                        let bytes = message::build_request(
                            self.mac,
                            self.fsm.xid(),
                            self.secs(),
                            self.fsm.state(),
                            requested_addr,
                            server_id,
                            unicast_to,
                        );
                        match unicast_to {
                            Some(dst) => self.send_unicast(dst, bytes).await?,
                            None => self.send_broadcast(bytes).await?,
                        }
                    }
                    Action::SendDecline { addr, server_id } => {
                        let bytes = message::build_decline(self.mac, self.fsm.xid(), addr, server_id);
                        self.send_broadcast(bytes).await?;
                    }
                    Action::SendRelease { addr, server_addr } => {
                        let bytes = message::build_release(self.mac, self.fsm.xid(), addr, server_addr);
                        self.send_unicast(server_addr, bytes).await?;
                    }
                    Action::StartArpProbe { addr } => {
                        let outcome = self.arp.probe(addr).await?;
                        let event = match outcome {
                            ProbeOutcome::Available => Event::ProbeOk,
                            ProbeOutcome::Conflict => Event::ProbeConflict,
                        };
                        self.dispatch(event).await?;
                    }
                    Action::ArmRetransmit(d) => self.timers.arm(TimerKind::Retransmit, Instant::now() + d),
                    Action::ArmRequestTimeout(d) => self.timers.arm(TimerKind::RequestTimeout, Instant::now() + d),
                    Action::ArmRenewTimer(d) => self.timers.arm(TimerKind::Renew, Instant::now() + d),
                    Action::ArmRebindTimer(d) => self.timers.arm(TimerKind::Rebind, Instant::now() + d),
                    Action::ArmExpireTimer(d) => self.timers.arm(TimerKind::Expire, Instant::now() + d),
                    Action::ArmNakBackoff(d) => self.timers.arm(TimerKind::NakBackoff, Instant::now() + d),
                    Action::CancelAllTimers => self.timers.clear_all(),
                    Action::Bound(lease) => self.on_bound(lease).await?,
                    Action::Dropped(reason) => tracing::info!(reason, "dhcp4"),
                }
            }
            Ok(())
        })
    }

    async fn on_bound(&mut self, lease: Lease) -> Result<(), Error> {
        let prefix_len = lease.subnet_mask.map(mask_to_prefix_len).unwrap_or(24);

        // Open the bound UDP socket before dropping the raw one, so a
        // send/recv in flight never finds neither transport present.
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT)).await?;
        udp.set_broadcast(true)?;
        self.udp = Some(udp);
        self.raw = None;

        self.netlink.add_addr(self.ifindex, IpAddr::V4(lease.your_addr), prefix_len).await?;

        tracing::info!(addr = %lease.your_addr, prefix_len, "dhcp4: bound");
        // Route installation, lease persistence, and hook execution are
        // not implemented yet (separate concerns; see PLAN.md).
        Ok(())
    }

    async fn send_broadcast(&self, payload: Vec<u8>) -> Result<(), Error> {
        if let Some(udp) = &self.udp {
            udp.send_to(&payload, (Ipv4Addr::BROADCAST, DHCP_SERVER_PORT)).await?;
        } else if let Some(raw) = &self.raw {
            let frame = raw_frame::build_udp_frame(
                self.mac,
                BROADCAST_MAC,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST,
                DHCP_CLIENT_PORT,
                DHCP_SERVER_PORT,
                &payload,
            );
            raw.send_frame(&frame).await?;
        }
        Ok(())
    }

    async fn send_unicast(&self, dst: Ipv4Addr, payload: Vec<u8>) -> Result<(), Error> {
        if let Some(udp) = &self.udp {
            udp.send_to(&payload, (dst, DHCP_SERVER_PORT)).await?;
        } else if let Some(raw) = &self.raw {
            // Not exercised by this FSM in practice (unicast is only used
            // once bound), but handled defensively: we have no ARP entry
            // for `dst` pre-bind, so this can only ever reach it if `dst`
            // happens to be on-link and the switch floods the broadcast
            // destination anyway.
            let frame = raw_frame::build_udp_frame(
                self.mac,
                BROADCAST_MAC,
                Ipv4Addr::UNSPECIFIED,
                dst,
                DHCP_CLIENT_PORT,
                DHCP_SERVER_PORT,
                &payload,
            );
            raw.send_frame(&frame).await?;
        }
        Ok(())
    }

    async fn recv_event(&self) -> Result<Option<Event>, Error> {
        let mut buf = vec![0u8; 2048];
        if let Some(udp) = &self.udp {
            let (n, _from) = udp.recv_from(&mut buf).await?;
            return Ok(message::parse_reply(&buf[..n], &self.mac, self.fsm.xid()));
        }
        if let Some(raw) = &self.raw {
            let n = raw.recv_frame(&mut buf).await?;
            if let Some(parsed) = raw_frame::parse_udp_frame(&buf[..n]) {
                if parsed.dst_port == DHCP_CLIENT_PORT {
                    return Ok(message::parse_reply(parsed.payload, &self.mac, self.fsm.xid()));
                }
            }
            return Ok(None);
        }
        // Both transports absent only during the brief window inside
        // on_bound before the swap completes; nothing to receive on yet.
        std::future::pending::<()>().await;
        unreachable!()
    }
}

fn mask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}
