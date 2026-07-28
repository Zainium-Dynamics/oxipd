//! Manual Ethernet + IPv4 + UDP framing for the pre-address-bind window
//! (DISCOVER/REQUEST-in-SELECTING/REBOOT/DECLINE): before an address is
//! configured, a normal UDP socket can't reliably send/receive DHCP's
//! broadcast traffic, so oxipd builds the whole frame itself over a raw
//! `AF_PACKET` socket (see `oxipd_net::packet`) and computes checksums by
//! hand (`oxipd_net::checksum`), exactly like dhcpcd's own comment at
//! `dhcp.c` explains for this same window. Still pure/no I/O.

use std::net::Ipv4Addr;

use oxipd_net::checksum;
use oxipd_net::packet::{build_ethernet_frame, parse_ethernet_frame, MacAddr, ETH_P_IP};

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPPROTO_UDP: u8 = 17;

/// Build a complete Ethernet/IPv4/UDP frame carrying `payload`, from
/// `src_ip:src_port` to `dst_ip:dst_port`, with both the IPv4 header
/// checksum and the UDP checksum computed by hand.
pub fn build_udp_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    udp.extend_from_slice(payload);
    let udp_cksum = checksum::udp_checksum_v4(src_ip, dst_ip, &udp);
    udp[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    let ip_total_len = IPV4_MIN_HEADER_LEN + udp.len();
    let mut ip = vec![0u8; IPV4_MIN_HEADER_LEN];
    ip[0] = 0x45; // version 4, IHL 5 (no options)
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: Don't Fragment
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_UDP;
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = checksum::checksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let mut ip_udp = ip;
    ip_udp.extend_from_slice(&udp);

    build_ethernet_frame(dst_mac, src_mac, ETH_P_IP, &ip_udp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUdpFrame<'a> {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    /// `false` if the UDP checksum didn't validate — some NICs deliver a
    /// frame before hardware checksum offload has finished computing it,
    /// so callers should treat this as a warning-worthy oddity, not an
    /// automatic reject (dhcpcd's own `BPF_PARTIALCSUM` handling exists
    /// for the same reason).
    pub udp_checksum_valid: bool,
    pub payload: &'a [u8],
}

/// Parse a captured raw frame as Ethernet/IPv4/UDP. Returns `None` for
/// anything that isn't that exact shape, or whose IPv4 header checksum is
/// invalid (unlike the UDP checksum, IP header checksum offload isn't a
/// real-world concern, so a bad one means a genuinely corrupt/malicious
/// packet). Never panics on truncated/malformed input.
pub fn parse_udp_frame(frame: &[u8]) -> Option<ParsedUdpFrame<'_>> {
    let eth = parse_ethernet_frame(frame)?;
    if eth.ethertype != ETH_P_IP {
        return None;
    }
    let ip = eth.payload;
    if ip.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let version = ip[0] >> 4;
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if version != 4 || ihl < IPV4_MIN_HEADER_LEN || ip.len() < ihl {
        return None;
    }
    if ip[9] != IPPROTO_UDP {
        return None;
    }
    if checksum::checksum(&ip[..ihl]) != 0 {
        return None;
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len > ip.len() || total_len < ihl {
        return None;
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let udp = &ip[ihl..total_len];
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len > udp.len() || udp_len < UDP_HEADER_LEN {
        return None;
    }

    let claimed_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    let udp_checksum_valid = if claimed_checksum == 0 {
        // 0 means "no checksum computed" (RFC 768) — nothing to validate.
        true
    } else {
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip.octets());
        pseudo[4..8].copy_from_slice(&dst_ip.octets());
        pseudo[9] = IPPROTO_UDP;
        pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
        checksum::finish(checksum::partial_sum(&pseudo, checksum::partial_sum(&udp[..udp_len], 0))) == 0
    };

    Some(ParsedUdpFrame {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        udp_checksum_valid,
        payload: &udp[UDP_HEADER_LEN..udp_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: MacAddr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: MacAddr = oxipd_net::packet::BROADCAST_MAC;

    #[test]
    fn round_trips_a_broadcast_dhcp_style_frame() {
        let payload = b"pretend-dhcp-payload";
        let frame = build_udp_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            payload,
        );

        let parsed = parse_udp_frame(&frame).expect("parses");
        assert_eq!(parsed.src_ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(parsed.dst_ip, Ipv4Addr::BROADCAST);
        assert_eq!(parsed.src_port, DHCP_CLIENT_PORT);
        assert_eq!(parsed.dst_port, DHCP_SERVER_PORT);
        assert!(parsed.udp_checksum_valid);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn round_trips_a_unicast_frame_with_real_addresses() {
        let payload = b"renew";
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let frame = build_udp_frame(SRC_MAC, [0xaa; 6], src, dst, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, payload);
        let parsed = parse_udp_frame(&frame).expect("parses");
        assert_eq!(parsed.src_ip, src);
        assert_eq!(parsed.dst_ip, dst);
        assert!(parsed.udp_checksum_valid);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn corrupted_ip_checksum_is_rejected() {
        let mut frame = build_udp_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            b"x",
        );
        // Flip a byte inside the IPv4 header (TTL field) without fixing up
        // the checksum.
        let ttl_offset = oxipd_net::packet::ETH_HLEN + 8;
        frame[ttl_offset] ^= 0xff;
        assert_eq!(parse_udp_frame(&frame), None);
    }

    #[test]
    fn corrupted_udp_payload_is_flagged_not_rejected() {
        let mut frame = build_udp_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            b"hello",
        );
        // Corrupt a payload byte (past the IP header, inside the UDP
        // payload) without touching the IP header checksum: the frame
        // must still parse (real NICs can deliver UDP before checksum
        // offload completes) but flag the UDP checksum as invalid.
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        let parsed = parse_udp_frame(&frame).expect("still parses");
        assert!(!parsed.udp_checksum_valid);
    }

    #[test]
    fn non_ip_ethertype_is_rejected() {
        let frame = build_ethernet_frame(DST_MAC, SRC_MAC, oxipd_net::packet::ETH_P_ARP, &[0u8; 28]);
        assert_eq!(parse_udp_frame(&frame), None);
    }

    #[test]
    fn truncated_frame_does_not_panic() {
        assert_eq!(parse_udp_frame(&[0u8; 20]), None);
    }
}
