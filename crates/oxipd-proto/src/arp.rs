//! ARP packet codec (RFC 826), the payload carried inside an Ethernet
//! frame of type `ETH_P_ARP` for IPv4-over-Ethernet ARP — the wire format
//! `oxipd_core::arp`'s RFC 5227 probe/announce/defend engine sends and
//! parses.

use std::net::Ipv4Addr;

pub const HTYPE_ETHERNET: u16 = 1;
pub const PTYPE_IPV4: u16 = 0x0800;
pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

/// Wire length of an Ethernet/IPv4 ARP packet: 8-byte fixed header + 2 *
/// (6-byte hardware address + 4-byte protocol address).
pub const PACKET_LEN: usize = 28;

pub type MacAddr = [u8; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_hw: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_hw: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parse an Ethernet/IPv4 ARP packet. Returns `None` for anything
    /// that isn't exactly that shape (wrong hardware/protocol type or
    /// address lengths, or too short) rather than erroring — ARP traffic
    /// is untrusted network input and other hardware/protocol
    /// combinations are simply not oxipd's concern.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < PACKET_LEN {
            return None;
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen = buf[4];
        let plen = buf[5];
        if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
            return None;
        }
        let operation = u16::from_be_bytes([buf[6], buf[7]]);

        let mut sender_hw = [0u8; 6];
        sender_hw.copy_from_slice(&buf[8..14]);
        let sender_ip = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);

        let mut target_hw = [0u8; 6];
        target_hw.copy_from_slice(&buf[18..24]);
        let target_ip = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);

        Some(ArpPacket {
            operation,
            sender_hw,
            sender_ip,
            target_hw,
            target_ip,
        })
    }

    pub fn build(&self) -> [u8; PACKET_LEN] {
        let mut buf = [0u8; PACKET_LEN];
        buf[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        buf[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        buf[4] = 6;
        buf[5] = 4;
        buf[6..8].copy_from_slice(&self.operation.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sender_hw);
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        buf[18..24].copy_from_slice(&self.target_hw);
        buf[24..28].copy_from_slice(&self.target_ip.octets());
        buf
    }

    /// Build an RFC 5227 probe: sender IP unspecified, sender/target
    /// hardware and target IP identify what's being probed for.
    pub fn probe(our_mac: MacAddr, target_ip: Ipv4Addr) -> Self {
        ArpPacket {
            operation: OP_REQUEST,
            sender_hw: our_mac,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_hw: [0; 6],
            target_ip,
        }
    }

    /// Build an RFC 5227 announcement/gratuitous ARP: sender and target
    /// address are the same (the address being claimed/defended).
    pub fn announcement(our_mac: MacAddr, addr: Ipv4Addr) -> Self {
        ArpPacket {
            operation: OP_REQUEST,
            sender_hw: our_mac,
            sender_ip: addr,
            target_hw: [0; 6],
            target_ip: addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_probe() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = ArpPacket::probe(mac, Ipv4Addr::new(192, 168, 1, 42));
        let bytes = pkt.build();
        let parsed = ArpPacket::parse(&bytes).expect("parses");
        assert_eq!(parsed, pkt);
        assert_eq!(parsed.sender_ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn round_trips_an_announcement() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let addr = Ipv4Addr::new(169, 254, 5, 6);
        let pkt = ArpPacket::announcement(mac, addr);
        let bytes = pkt.build();
        let parsed = ArpPacket::parse(&bytes).expect("parses");
        assert_eq!(parsed.sender_ip, addr);
        assert_eq!(parsed.target_ip, addr);
    }

    #[test]
    fn rejects_wrong_hardware_type() {
        let mut buf = ArpPacket::probe([0; 6], Ipv4Addr::UNSPECIFIED).build();
        buf[0..2].copy_from_slice(&6u16.to_be_bytes()); // not Ethernet
        assert_eq!(ArpPacket::parse(&buf), None);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(ArpPacket::parse(&[0u8; 10]), None);
    }
}
