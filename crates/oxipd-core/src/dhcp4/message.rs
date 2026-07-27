//! Bridges the pure [`super::fsm`] core to actual DHCPv4 wire bytes: builds
//! a message for each [`Action`] that sends one, and parses a received
//! message into the [`Event`] the FSM should react to (or `None` if it's
//! not a reply we should react to at all). Still pure/no I/O — the async
//! shell that actually sends/receives these bytes over sockets is a
//! separate, not-yet-implemented layer (see PLAN.md's M3 milestone).

use std::net::Ipv4Addr;

use oxipd_proto::dhcpv4::{opt, MessageBuilder, MessageType, Message, BOOTREPLY, BOOTREQUEST};

use super::fsm::{Event, State};
use super::lease::Lease;

/// The DHCP options oxipd-core currently acts on; requested via the
/// parameter-request-list on every outbound message.
const PARAMETER_REQUEST_LIST: &[u8] = &[
    opt::SUBNET_MASK,
    opt::ROUTER,
    opt::DNS_SERVER,
    opt::DNS_DOMAIN,
    opt::BROADCAST,
    opt::LEASE_TIME,
    opt::RENEWAL_TIME,
    opt::REBINDING_TIME,
];

pub fn build_discover(mac: [u8; 6], xid: u32, secs: u16, requested_addr: Option<Ipv4Addr>) -> Vec<u8> {
    let mut b = MessageBuilder::new(BOOTREQUEST, xid);
    b.chaddr(&mac).secs(secs).broadcast_flag(true).message_type(MessageType::Discover);
    b.add_option(opt::PARAMETER_REQUEST_LIST, PARAMETER_REQUEST_LIST);
    if let Some(addr) = requested_addr {
        b.add_option(opt::REQUESTED_IP_ADDRESS, &addr.octets());
    }
    b.build()
}

/// Build the wire bytes for a `SendRequest` action. `fsm_state`
/// disambiguates [`State::Reboot`] (no address configured yet, `ciaddr`
/// zero) from [`State::Rebind`] (address already configured, `ciaddr` set)
/// since both share `unicast_to: None, server_id: None` in the action
/// itself — see RFC 2131 table 4.
pub fn build_request(
    mac: [u8; 6],
    xid: u32,
    secs: u16,
    fsm_state: State,
    requested_addr: Ipv4Addr,
    server_id: Option<Ipv4Addr>,
    unicast_to: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut b = MessageBuilder::new(BOOTREQUEST, xid);
    b.chaddr(&mac).secs(secs).message_type(MessageType::Request);

    if unicast_to.is_some() {
        // RENEWING: already have a working IP stack, unicast to the known
        // server; ciaddr conveys the address, so no need for option 50.
        b.ciaddr(requested_addr).broadcast_flag(false);
    } else if fsm_state == State::Rebind {
        // REBINDING: still have the address configured, but don't know
        // which server (if any) will answer, so broadcast.
        b.ciaddr(requested_addr).broadcast_flag(true);
    } else {
        // SELECTING or INIT-REBOOT: no configured address yet.
        b.broadcast_flag(true);
        b.add_option(opt::REQUESTED_IP_ADDRESS, &requested_addr.octets());
    }
    if let Some(sid) = server_id {
        b.add_option(opt::SERVER_IDENTIFIER, &sid.octets());
    }
    b.add_option(opt::PARAMETER_REQUEST_LIST, PARAMETER_REQUEST_LIST);
    b.build()
}

pub fn build_decline(mac: [u8; 6], xid: u32, addr: Ipv4Addr, server_id: Option<Ipv4Addr>) -> Vec<u8> {
    let mut b = MessageBuilder::new(BOOTREQUEST, xid);
    b.chaddr(&mac).message_type(MessageType::Decline);
    b.add_option(opt::REQUESTED_IP_ADDRESS, &addr.octets());
    if let Some(sid) = server_id {
        b.add_option(opt::SERVER_IDENTIFIER, &sid.octets());
    }
    b.build()
}

pub fn build_release(mac: [u8; 6], xid: u32, addr: Ipv4Addr, server_addr: Ipv4Addr) -> Vec<u8> {
    let mut b = MessageBuilder::new(BOOTREQUEST, xid);
    b.chaddr(&mac).ciaddr(addr).message_type(MessageType::Release);
    b.add_option(opt::SERVER_IDENTIFIER, &server_addr.octets());
    b.build()
}

/// Parse a received datagram into the FSM event it should produce, or
/// `None` if it's not a reply worth reacting to: not a well-formed DHCP
/// reply, addressed to a different transaction (xid) or a different
/// client (hardware address), or a message type oxipd-core doesn't act on
/// (e.g. `FORCERENEW`, deferred to a later milestone).
pub fn parse_reply(buf: &[u8], our_mac: &[u8; 6], expected_xid: u32) -> Option<Event> {
    let msg = Message::parse(buf).ok()?;
    if msg.op() != BOOTREPLY || msg.xid() != expected_xid {
        return None;
    }
    if msg.chaddr()[..6] != our_mac[..] {
        return None;
    }

    match msg.message_type().ok()? {
        MessageType::Offer => {
            let server_id = msg.option(opt::SERVER_IDENTIFIER).and_then(|d| ipv4(&d));
            Some(Event::Offer {
                xid: msg.xid(),
                offered_addr: msg.yiaddr(),
                server_id,
            })
        }
        MessageType::Ack => Some(Event::Ack {
            xid: msg.xid(),
            lease: Lease::from_message(&msg),
        }),
        MessageType::Nak => Some(Event::Nak { xid: msg.xid() }),
        _ => None,
    }
}

fn ipv4(data: &[u8]) -> Option<Ipv4Addr> {
    (data.len() >= 4).then(|| Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn parse(bytes: &[u8]) -> Message<'_> {
        Message::parse(bytes).unwrap()
    }

    #[test]
    fn discover_is_broadcast_with_prl_and_no_ciaddr() {
        let bytes = build_discover(MAC, 42, 3, None);
        let msg = parse(&bytes);
        assert_eq!(msg.xid(), 42);
        assert_eq!(msg.secs(), 3);
        assert!(msg.broadcast());
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.message_type().unwrap(), MessageType::Discover);
        assert_eq!(msg.option(opt::PARAMETER_REQUEST_LIST).unwrap(), PARAMETER_REQUEST_LIST.to_vec());
    }

    #[test]
    fn selecting_request_includes_requested_ip_and_server_id() {
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let bytes = build_request(MAC, 1, 0, State::Request, addr, Some(server), None);
        let msg = parse(&bytes);
        assert!(msg.broadcast());
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.option(opt::REQUESTED_IP_ADDRESS).unwrap(), addr.octets().to_vec());
        assert_eq!(msg.option(opt::SERVER_IDENTIFIER).unwrap(), server.octets().to_vec());
    }

    #[test]
    fn init_reboot_request_has_no_server_id() {
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let bytes = build_request(MAC, 1, 0, State::Reboot, addr, None, None);
        let msg = parse(&bytes);
        assert!(msg.broadcast());
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.option(opt::REQUESTED_IP_ADDRESS).unwrap(), addr.octets().to_vec());
        assert!(msg.option(opt::SERVER_IDENTIFIER).is_none());
    }

    #[test]
    fn renewing_request_is_unicast_with_ciaddr_and_no_requested_ip() {
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let bytes = build_request(MAC, 1, 0, State::Renew, addr, None, Some(server));
        let msg = parse(&bytes);
        assert!(!msg.broadcast());
        assert_eq!(msg.ciaddr(), addr);
        assert!(msg.option(opt::REQUESTED_IP_ADDRESS).is_none());
        assert!(msg.option(opt::SERVER_IDENTIFIER).is_none());
    }

    #[test]
    fn rebinding_request_broadcasts_with_ciaddr_set() {
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        let bytes = build_request(MAC, 1, 0, State::Rebind, addr, None, None);
        let msg = parse(&bytes);
        assert!(msg.broadcast());
        assert_eq!(msg.ciaddr(), addr);
        assert!(msg.option(opt::REQUESTED_IP_ADDRESS).is_none());
    }

    #[test]
    fn parses_offer_ack_and_nak() {
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(10, 0, 0, 1);

        let mut b = MessageBuilder::new(BOOTREPLY, 7);
        b.chaddr(&MAC)
            .yiaddr(addr)
            .message_type(MessageType::Offer)
            .add_option(opt::SERVER_IDENTIFIER, &server.octets());
        let offer_bytes = b.build();
        match parse_reply(&offer_bytes, &MAC, 7) {
            Some(Event::Offer { xid, offered_addr, server_id }) => {
                assert_eq!(xid, 7);
                assert_eq!(offered_addr, addr);
                assert_eq!(server_id, Some(server));
            }
            other => panic!("expected Offer, got {other:?}"),
        }

        let mut b = MessageBuilder::new(BOOTREPLY, 8);
        b.chaddr(&MAC)
            .yiaddr(addr)
            .message_type(MessageType::Ack)
            .add_option(opt::SERVER_IDENTIFIER, &server.octets())
            .add_option(opt::LEASE_TIME, &3600u32.to_be_bytes());
        let ack_bytes = b.build();
        match parse_reply(&ack_bytes, &MAC, 8) {
            Some(Event::Ack { xid, lease }) => {
                assert_eq!(xid, 8);
                assert_eq!(lease.your_addr, addr);
                assert_eq!(lease.server_addr, Some(server));
                assert_eq!(lease.lease_time, 3600);
            }
            other => panic!("expected Ack, got {other:?}"),
        }

        let mut b = MessageBuilder::new(BOOTREPLY, 9);
        b.chaddr(&MAC).message_type(MessageType::Nak);
        let nak_bytes = b.build();
        assert!(matches!(parse_reply(&nak_bytes, &MAC, 9), Some(Event::Nak { xid: 9 })));
    }

    #[test]
    fn wrong_xid_or_mac_is_rejected() {
        let mut b = MessageBuilder::new(BOOTREPLY, 7);
        b.chaddr(&MAC).message_type(MessageType::Offer);
        let bytes = b.build();

        assert!(parse_reply(&bytes, &MAC, 99).is_none());

        let other_mac = [0u8; 6];
        assert!(parse_reply(&bytes, &other_mac, 7).is_none());
    }

    #[test]
    fn bootrequest_replies_are_ignored() {
        // A reply we somehow captured our own request in (loopback/bridge
        // artifact) must never be mistaken for a server reply.
        let mut b = MessageBuilder::new(BOOTREQUEST, 7);
        b.chaddr(&MAC).message_type(MessageType::Discover);
        let bytes = b.build();
        assert!(parse_reply(&bytes, &MAC, 7).is_none());
    }
}
