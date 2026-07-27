//! The DHCPv4 client state machine, as a pure "core": [`Dhcp4Fsm::handle`]
//! takes an [`Event`] and returns the [`Action`]s the caller (an async
//! "shell" driving real sockets, timers, and netlink — not implemented
//! yet, see PLAN.md's M3 milestone) must perform. Keeping the state
//! machine itself free of any I/O means every transition in this file is
//! unit-testable without a network namespace.
//!
//! States mirror dhcpcd's `DHS_*` enum (dhcp.c), minus the unused
//! `DHS_RENEW_REQUESTED`; `Inform` (static/BOOTP-inform-only mode) is not
//! part of this pass and is left for a follow-up increment.

use std::net::Ipv4Addr;
use std::time::Duration;

use super::lease::Lease;
use super::timing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Init,
    Discover,
    Request,
    Reboot,
    Probe,
    Bound,
    Renew,
    Rebind,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// Begin a fresh acquisition (no usable saved lease).
    Start,
    /// Begin with a previously saved lease (RFC 2131 INIT-REBOOT).
    StartReboot(Lease),
    /// The current retransmit timer fired.
    RetransmitTimeout,
    /// The SELECTING/INIT-REBOOT "give up on this offer" watchdog fired.
    RequestTimeoutExpired,
    /// T1 fired (only meaningful from [`State::Bound`]).
    RenewTimerFired,
    /// T2 fired (only meaningful from [`State::Renew`]).
    RebindTimerFired,
    /// The full lease lifetime elapsed with no successful renew/rebind.
    LeaseExpired,
    /// The NAK backoff timer elapsed; time to try a fresh DISCOVER.
    NakBackoffElapsed,
    /// A valid OFFER was received while in [`State::Discover`].
    Offer {
        xid: u32,
        offered_addr: Ipv4Addr,
        server_id: Option<Ipv4Addr>,
    },
    /// A valid ACK was received.
    Ack { xid: u32, lease: Lease },
    /// A valid NAK was received.
    Nak { xid: u32 },
    /// ARP DAD on the candidate address completed with no conflict.
    ProbeOk,
    /// ARP DAD (or a later defend) found a conflict.
    ProbeConflict,
    /// The application asked to release the current lease.
    ReleaseRequested,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    SendDiscover,
    /// Covers every RFC 2131 REQUEST shape: SELECTING (`server_id: Some`,
    /// `unicast_to: None`), INIT-REBOOT/REBINDING (`server_id: None`,
    /// `unicast_to: None`, broadcast), and RENEWING (`unicast_to: Some`).
    SendRequest {
        requested_addr: Ipv4Addr,
        server_id: Option<Ipv4Addr>,
        unicast_to: Option<Ipv4Addr>,
    },
    SendDecline { addr: Ipv4Addr, server_id: Option<Ipv4Addr> },
    SendRelease { addr: Ipv4Addr, server_addr: Ipv4Addr },
    StartArpProbe { addr: Ipv4Addr },
    ArmRetransmit(Duration),
    ArmRequestTimeout(Duration),
    ArmRenewTimer(Duration),
    ArmRebindTimer(Duration),
    ArmExpireTimer(Duration),
    ArmNakBackoff(Duration),
    CancelAllTimers,
    /// The lease is now active; caller should configure the address,
    /// install routes, and run hooks.
    Bound(Lease),
    /// Informational: caller may want to log/run a hook for `$reason`.
    Dropped(&'static str),
}

#[derive(Debug, Clone)]
pub struct Dhcp4Fsm {
    state: State,
    xid: u32,
    interval: Option<Duration>,
    nak_backoff: Option<Duration>,
    requested_addr: Option<Ipv4Addr>,
    requested_server_id: Option<Ipv4Addr>,
    probing_lease: Option<Lease>,
    current: Option<Lease>,
}

impl Default for Dhcp4Fsm {
    fn default() -> Self {
        Self::new()
    }
}

impl Dhcp4Fsm {
    pub fn new() -> Self {
        Dhcp4Fsm {
            state: State::Init,
            xid: 0,
            interval: None,
            nak_backoff: None,
            requested_addr: None,
            requested_server_id: None,
            probing_lease: None,
            current: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn xid(&self) -> u32 {
        self.xid
    }

    pub fn current_lease(&self) -> Option<&Lease> {
        self.current.as_ref()
    }

    fn new_xid(&mut self) {
        self.xid = rand::random();
    }

    /// Reset into a brand-new SELECTING/DISCOVER cycle.
    fn start_discover(&mut self) -> Vec<Action> {
        self.new_xid();
        self.state = State::Discover;
        self.interval = None;
        self.requested_addr = None;
        self.requested_server_id = None;
        self.probing_lease = None;
        self.retransmit(Action::SendDiscover)
    }

    /// Advance the shared retransmit backoff and pair it with the given
    /// "(re)send this" action plus the timer to arm for the next one.
    fn retransmit(&mut self, send: Action) -> Vec<Action> {
        let next = timing::next_retransmit_interval(self.interval);
        self.interval = Some(next);
        vec![send, Action::ArmRetransmit(timing::jittered(next))]
    }

    fn bind(&mut self, lease: Lease) -> Vec<Action> {
        self.state = State::Bound;
        self.interval = None;
        self.nak_backoff = None;
        self.requested_addr = None;
        self.requested_server_id = None;
        self.probing_lease = None;

        let mut actions = vec![Action::Bound(lease.clone())];
        if lease.lease_time != u32::MAX {
            actions.push(Action::ArmRenewTimer(Duration::from_secs(lease.renewal_time as u64)));
            actions.push(Action::ArmRebindTimer(Duration::from_secs(lease.rebinding_time as u64)));
            actions.push(Action::ArmExpireTimer(Duration::from_secs(lease.lease_time as u64)));
        }
        self.current = Some(lease);
        actions
    }

    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Start => {
                if self.state != State::Init {
                    return vec![];
                }
                self.start_discover()
            }

            Event::StartReboot(lease) => {
                if self.state != State::Init {
                    return vec![];
                }
                self.new_xid();
                self.state = State::Reboot;
                self.interval = None;
                self.requested_addr = Some(lease.your_addr);
                self.requested_server_id = None;
                let mut actions = self.retransmit(Action::SendRequest {
                    requested_addr: lease.your_addr,
                    server_id: None,
                    unicast_to: None,
                });
                actions.push(Action::ArmRequestTimeout(timing::DEFAULT_REQUEST_TIMEOUT));
                actions
            }

            Event::RetransmitTimeout => match self.state {
                State::Discover => self.retransmit(Action::SendDiscover),
                State::Request | State::Reboot => {
                    let requested_addr = self.requested_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let server_id = self.requested_server_id;
                    self.retransmit(Action::SendRequest {
                        requested_addr,
                        server_id,
                        unicast_to: None,
                    })
                }
                State::Renew => {
                    let (addr, server) = self
                        .current
                        .as_ref()
                        .map(|l| (l.your_addr, l.server_addr))
                        .unwrap_or((Ipv4Addr::UNSPECIFIED, None));
                    self.retransmit(Action::SendRequest {
                        requested_addr: addr,
                        server_id: None,
                        unicast_to: server,
                    })
                }
                State::Rebind => {
                    let addr = self.current.as_ref().map(|l| l.your_addr).unwrap_or(Ipv4Addr::UNSPECIFIED);
                    self.retransmit(Action::SendRequest {
                        requested_addr: addr,
                        server_id: None,
                        unicast_to: None,
                    })
                }
                _ => vec![],
            },

            Event::RequestTimeoutExpired => match self.state {
                State::Request | State::Reboot => {
                    let mut actions = vec![Action::CancelAllTimers, Action::Dropped("request timed out")];
                    actions.extend(self.start_discover());
                    actions
                }
                _ => vec![],
            },

            Event::Offer {
                xid,
                offered_addr,
                server_id,
            } => {
                if self.state != State::Discover || xid != self.xid {
                    return vec![];
                }
                self.state = State::Request;
                self.interval = None;
                self.requested_addr = Some(offered_addr);
                self.requested_server_id = server_id;
                let mut actions = self.retransmit(Action::SendRequest {
                    requested_addr: offered_addr,
                    server_id,
                    unicast_to: None,
                });
                actions.push(Action::ArmRequestTimeout(timing::DEFAULT_REQUEST_TIMEOUT));
                actions
            }

            Event::Ack { xid, lease } => {
                if xid != self.xid {
                    return vec![];
                }
                if !matches!(self.state, State::Request | State::Reboot | State::Renew | State::Rebind) {
                    return vec![];
                }
                // dhcpcd ARP-probes on every (re)assignment, not just the
                // first one — defends against the address having been
                // silently taken over during our own lease's lifetime.
                self.state = State::Probe;
                let addr = lease.your_addr;
                self.probing_lease = Some(lease);
                vec![Action::CancelAllTimers, Action::StartArpProbe { addr }]
            }

            Event::Nak { xid } => {
                if xid != self.xid {
                    return vec![];
                }
                if !matches!(self.state, State::Request | State::Reboot | State::Renew | State::Rebind) {
                    return vec![];
                }
                self.current = None;
                self.requested_addr = None;
                self.requested_server_id = None;
                let backoff = timing::next_nak_backoff(self.nak_backoff);
                self.nak_backoff = Some(backoff);
                self.state = State::Init;
                vec![
                    Action::CancelAllTimers,
                    Action::Dropped("NAK"),
                    Action::ArmNakBackoff(backoff),
                ]
            }

            Event::NakBackoffElapsed => {
                if self.state != State::Init {
                    return vec![];
                }
                self.start_discover()
            }

            Event::ProbeOk => {
                if self.state != State::Probe {
                    return vec![];
                }
                match self.probing_lease.take() {
                    Some(lease) => self.bind(lease),
                    None => vec![],
                }
            }

            Event::ProbeConflict => {
                if self.state != State::Probe {
                    return vec![];
                }
                let mut actions = vec![];
                if let Some(lease) = self.probing_lease.take() {
                    actions.push(Action::SendDecline {
                        addr: lease.your_addr,
                        server_id: lease.server_addr,
                    });
                }
                actions.push(Action::Dropped("address already in use (ARP conflict)"));
                actions.extend(self.start_discover());
                actions
            }

            Event::RenewTimerFired => {
                if self.state != State::Bound {
                    return vec![];
                }
                self.state = State::Renew;
                self.interval = None;
                let server = self.current.as_ref().and_then(|l| l.server_addr);
                let addr = self.current.as_ref().map(|l| l.your_addr).unwrap_or(Ipv4Addr::UNSPECIFIED);
                self.retransmit(Action::SendRequest {
                    requested_addr: addr,
                    server_id: None,
                    unicast_to: server,
                })
            }

            Event::RebindTimerFired => {
                if self.state != State::Renew {
                    return vec![];
                }
                self.state = State::Rebind;
                self.interval = None;
                let addr = self.current.as_ref().map(|l| l.your_addr).unwrap_or(Ipv4Addr::UNSPECIFIED);
                self.retransmit(Action::SendRequest {
                    requested_addr: addr,
                    server_id: None,
                    unicast_to: None,
                })
            }

            Event::LeaseExpired => {
                if !matches!(self.state, State::Bound | State::Renew | State::Rebind) {
                    return vec![];
                }
                self.current = None;
                let mut actions = vec![Action::CancelAllTimers, Action::Dropped("lease expired")];
                actions.extend(self.start_discover());
                actions
            }

            Event::ReleaseRequested => {
                let Some(lease) = self.current.take() else {
                    return vec![];
                };
                self.state = State::Init;
                self.interval = None;
                let server_addr = lease.server_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
                vec![
                    Action::CancelAllTimers,
                    Action::SendRelease {
                        addr: lease.your_addr,
                        server_addr,
                    },
                    Action::Dropped("released"),
                ]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(addr: Ipv4Addr, server: Ipv4Addr, lease_time: u32) -> Lease {
        Lease {
            your_addr: addr,
            server_addr: Some(server),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            broadcast: None,
            routers: vec![],
            dns_servers: vec![],
            domain_name: None,
            lease_time,
            renewal_time: lease_time / 2,
            rebinding_time: lease_time * 7 / 8,
        }
    }

    #[test]
    fn full_happy_path_discover_through_bound() {
        let mut fsm = Dhcp4Fsm::new();
        let actions = fsm.handle(Event::Start);
        assert_eq!(fsm.state(), State::Discover);
        assert!(matches!(actions[0], Action::SendDiscover));
        let xid = fsm.xid();

        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let actions = fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: Some(server),
        });
        assert_eq!(fsm.state(), State::Request);
        assert!(matches!(
            actions[0],
            Action::SendRequest { requested_addr, server_id: Some(s), unicast_to: None }
                if requested_addr == addr && s == server
        ));

        let actions = fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 3600),
        });
        assert_eq!(fsm.state(), State::Probe);
        assert_eq!(actions, vec![Action::CancelAllTimers, Action::StartArpProbe { addr }]);

        let actions = fsm.handle(Event::ProbeOk);
        assert_eq!(fsm.state(), State::Bound);
        assert!(matches!(actions[0], Action::Bound(ref l) if l.your_addr == addr));
        assert_eq!(fsm.current_lease().unwrap().your_addr, addr);
    }

    #[test]
    fn offer_with_wrong_xid_is_ignored() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let actions = fsm.handle(Event::Offer {
            xid: fsm.xid().wrapping_add(1),
            offered_addr: Ipv4Addr::new(10, 0, 0, 1),
            server_id: None,
        });
        assert!(actions.is_empty());
        assert_eq!(fsm.state(), State::Discover);
    }

    #[test]
    fn retransmit_backs_off_and_resends_for_the_current_state() {
        let mut fsm = Dhcp4Fsm::new();
        // Start's own retransmit already consumes the base 4s interval
        // (jittered range [3,5]s), so the first RetransmitTimeout doubles
        // to 8s ([7,9]s jittered) and the second to 16s ([15,17]s).
        fsm.handle(Event::Start);
        let a1 = fsm.handle(Event::RetransmitTimeout);
        let a2 = fsm.handle(Event::RetransmitTimeout);
        let (Action::SendDiscover, Action::ArmRetransmit(d1)) = (&a1[0], &a1[1]) else {
            panic!("unexpected actions: {a1:?}")
        };
        let (Action::SendDiscover, Action::ArmRetransmit(d2)) = (&a2[0], &a2[1]) else {
            panic!("unexpected actions: {a2:?}")
        };
        assert!(*d1 >= Duration::from_secs(7) && *d1 <= Duration::from_secs(9));
        assert!(*d2 >= Duration::from_secs(15) && *d2 <= Duration::from_secs(17));
    }

    #[test]
    fn nak_schedules_backoff_then_restarts_discover() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let xid = fsm.xid();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: None,
        });

        let actions = fsm.handle(Event::Nak { xid });
        assert_eq!(fsm.state(), State::Init);
        assert!(actions.iter().any(|a| matches!(a, Action::ArmNakBackoff(d) if *d == Duration::from_secs(1))));

        let actions = fsm.handle(Event::NakBackoffElapsed);
        assert_eq!(fsm.state(), State::Discover);
        assert!(matches!(actions[0], Action::SendDiscover));
        // A fresh cycle must use a new xid, not the NAK'd one.
        assert_ne!(fsm.xid(), xid);
    }

    #[test]
    fn probe_conflict_declines_and_restarts_discover() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let xid = fsm.xid();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: Some(server),
        });
        fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 3600),
        });

        let actions = fsm.handle(Event::ProbeConflict);
        assert_eq!(fsm.state(), State::Discover);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendDecline { addr: d, .. } if *d == addr)));
        assert!(fsm.current_lease().is_none());
    }

    #[test]
    fn renew_then_rebind_then_bound_again() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let xid = fsm.xid();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: Some(server),
        });
        fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 3600),
        });
        fsm.handle(Event::ProbeOk);
        assert_eq!(fsm.state(), State::Bound);

        // T1 fires: RENEWING, unicast to the known server.
        let actions = fsm.handle(Event::RenewTimerFired);
        assert_eq!(fsm.state(), State::Renew);
        assert!(matches!(
            actions[0],
            Action::SendRequest { unicast_to: Some(s), server_id: None, .. } if s == server
        ));

        // No reply; T2 fires: REBINDING, back to broadcast.
        let actions = fsm.handle(Event::RebindTimerFired);
        assert_eq!(fsm.state(), State::Rebind);
        assert!(matches!(
            actions[0],
            Action::SendRequest { unicast_to: None, server_id: None, .. }
        ));

        // Server (or a new one) finally answers; same xid throughout this
        // whole renew/rebind cycle since it's still the SAME transaction
        // as the original acquisition until a fresh DISCOVER happens.
        let new_xid = fsm.xid();
        let actions = fsm.handle(Event::Ack {
            xid: new_xid,
            lease: lease(addr, server, 7200),
        });
        assert_eq!(fsm.state(), State::Probe);
        assert_eq!(actions, vec![Action::CancelAllTimers, Action::StartArpProbe { addr }]);
        fsm.handle(Event::ProbeOk);
        assert_eq!(fsm.state(), State::Bound);
        assert_eq!(fsm.current_lease().unwrap().lease_time, 7200);
    }

    #[test]
    fn lease_expiry_drops_and_restarts() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let xid = fsm.xid();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: Some(server),
        });
        fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 60),
        });
        fsm.handle(Event::ProbeOk);
        fsm.handle(Event::RenewTimerFired);
        fsm.handle(Event::RebindTimerFired);

        let actions = fsm.handle(Event::LeaseExpired);
        assert_eq!(fsm.state(), State::Discover);
        assert!(fsm.current_lease().is_none());
        assert!(actions.iter().any(|a| matches!(a, Action::Dropped("lease expired"))));
    }

    #[test]
    fn release_sends_release_and_returns_to_init() {
        let mut fsm = Dhcp4Fsm::new();
        fsm.handle(Event::Start);
        let xid = fsm.xid();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        fsm.handle(Event::Offer {
            xid,
            offered_addr: addr,
            server_id: Some(server),
        });
        fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 3600),
        });
        fsm.handle(Event::ProbeOk);

        let actions = fsm.handle(Event::ReleaseRequested);
        assert_eq!(fsm.state(), State::Init);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendRelease { addr: d, server_addr: s } if *d == addr && *s == server)));
        assert!(fsm.current_lease().is_none());
    }

    #[test]
    fn reboot_flow_probes_then_binds() {
        let mut fsm = Dhcp4Fsm::new();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let saved = lease(addr, server, 3600);

        let actions = fsm.handle(Event::StartReboot(saved));
        assert_eq!(fsm.state(), State::Reboot);
        assert!(matches!(
            actions[0],
            Action::SendRequest { requested_addr, server_id: None, unicast_to: None } if requested_addr == addr
        ));

        let xid = fsm.xid();
        fsm.handle(Event::Ack {
            xid,
            lease: lease(addr, server, 3600),
        });
        assert_eq!(fsm.state(), State::Probe);
        fsm.handle(Event::ProbeOk);
        assert_eq!(fsm.state(), State::Bound);
    }
}
