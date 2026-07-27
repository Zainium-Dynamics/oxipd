//! RFC 1071 Internet checksum, plus the IPv4/UDP pseudo-header variants
//! DHCPv4 needs to hand-build packets before an address is configured (see
//! oxipd-core::dhcp4's pre-bind raw-socket path).

use std::net::Ipv4Addr;

/// Fold `data` into a running ones'-complement sum. Call repeatedly (e.g.
/// once for a pseudo-header, once for the real payload) before [`finish`].
pub fn partial_sum(data: &[u8], mut sum: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = *chunks.remainder() {
        sum += (last as u32) << 8;
    }
    sum
}

/// Fold carries and take the ones' complement to produce the final
/// checksum field value.
pub fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One-shot checksum over a single contiguous buffer (e.g. an IPv4 header
/// with its checksum field zeroed).
pub fn checksum(data: &[u8]) -> u16 {
    finish(partial_sum(data, 0))
}

/// UDP checksum over an IPv4 pseudo-header + the UDP header+payload
/// (`udp_segment`'s own checksum field must be zeroed by the caller before
/// calling this). Per RFC 768, an all-zero result is sent as `0xffff`
/// instead, since zero means "no checksum computed".
pub fn udp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 17; // IPPROTO_UDP
    pseudo[10..12].copy_from_slice(&(udp_segment.len() as u16).to_be_bytes());

    let sum = partial_sum(&pseudo, partial_sum(udp_segment, 0));
    match finish(sum) {
        0 => 0xffff,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_header_checksum_matches_known_vector() {
        // Textbook example: src 172.16.10.99 -> dst 172.16.10.12, TCP,
        // checksum field (bytes 10..12) zeroed. Expected checksum 0xb1e6.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_eq!(checksum(&header), 0xb1e6);
    }

    #[test]
    fn udp_checksum_is_self_consistent() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(255, 255, 255, 255);

        // UDP header (8 bytes, checksum field zeroed) + a few payload bytes.
        let mut segment = vec![0u8; 8 + 5];
        segment[0..2].copy_from_slice(&68u16.to_be_bytes()); // src port
        segment[2..4].copy_from_slice(&67u16.to_be_bytes()); // dst port
        let len = segment.len() as u16;
        segment[4..6].copy_from_slice(&len.to_be_bytes());
        segment[8..].copy_from_slice(b"hello");

        let cs = udp_checksum_v4(src, dst, &segment);
        segment[6..8].copy_from_slice(&cs.to_be_bytes());

        // Recomputing over pseudo-header + segment-with-real-checksum
        // should now fold to all-ones, i.e. finish() == 0.
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src.octets());
        pseudo[4..8].copy_from_slice(&dst.octets());
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&len.to_be_bytes());
        let verify = finish(partial_sum(&pseudo, partial_sum(&segment, 0)));
        assert_eq!(verify, 0);
    }

    #[test]
    fn zero_checksum_result_becomes_0xffff() {
        // Craft an 8-byte segment (src/dst 0.0.0.0, so the pseudo-header
        // only contributes the proto byte (17) and the length word (8))
        // whose one nonzero word makes the total ones'-complement sum fold
        // to exactly 0xffff, i.e. finish() would yield 0x0000 pre-remap.
        // RFC 768 requires sending 0xffff instead since 0 means "no
        // checksum was computed".
        let src = Ipv4Addr::UNSPECIFIED;
        let dst = Ipv4Addr::UNSPECIFIED;
        let x: u16 = 0xffff - 17 - 8;
        let mut segment = [0u8; 8];
        segment[6..8].copy_from_slice(&x.to_be_bytes());

        // Sanity check the premise before asserting the remap behavior.
        let mut pseudo = [0u8; 12];
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(finish(partial_sum(&pseudo, partial_sum(&segment, 0))), 0);

        assert_eq!(udp_checksum_v4(src, dst, &segment), 0xffff);
    }
}
