//! SLAAC interface-identifier generation: RFC 4291/2464 Modified EUI-64
//! (derived straight from the interface's MAC) and RFC 7217 stable-private
//! addressing (derived from a persisted secret, so the address is stable
//! per-prefix/per-interface but doesn't leak the MAC to the network like
//! EUI-64 does). RFC 4941 temporary/privacy addresses (which additionally
//! need a persisted desync factor and periodic regeneration) are a
//! follow-up increment.

use std::net::Ipv6Addr;

use sha2::{Digest, Sha256};

pub type Iid = [u8; 8];

/// RFC 4291 Appendix A / RFC 2464 §4: insert `FF:FE` in the middle of the
/// MAC and flip the universal/local bit.
pub fn eui64_iid(mac: [u8; 6]) -> Iid {
    [mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]]
}

/// RFC 7217 §5: `F(prefix, net_iface, network_id, dad_counter, secret_key)`,
/// truncated to the leftmost 64 bits of a SHA-256 digest. `net_iface`
/// disambiguates interfaces sharing the same prefix (dhcpcd uses the
/// interface name); `network_id` further disambiguates by attachment
/// point (e.g. Wi-Fi SSID) when relevant, or is empty otherwise.
pub fn rfc7217_iid(prefix: Ipv6Addr, net_iface: &[u8], network_id: &[u8], dad_counter: u8, secret_key: &[u8]) -> Iid {
    let mut hasher = Sha256::new();
    hasher.update(&prefix.octets()[..8]); // network part only (first 64 bits)
    hasher.update(net_iface);
    hasher.update(network_id);
    hasher.update([dad_counter]);
    hasher.update(secret_key);
    let digest = hasher.finalize();
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&digest[..8]);
    iid
}

/// RFC 5453: IIDs reserved by other protocols that SLAAC must not pick —
/// the Subnet-Router anycast address (all-zero IID) and the RFC 2526
/// reserved anycast block (IIDs `...:xxxx:xx80` through `...:ffff:ffff`,
/// i.e. the top 7 bits of the last byte set).
pub fn is_reserved_iid(iid: &Iid) -> bool {
    if *iid == [0u8; 8] {
        return true;
    }
    iid[..7] == [0xff; 7] && iid[7] >= 0x80
}

/// Combine a received prefix (only its network part, first 64 bits, is
/// used — SLAAC always operates on /64s) with an interface identifier.
pub fn make_address(prefix: Ipv6Addr, iid: Iid) -> Ipv6Addr {
    let mut octets = prefix.octets();
    octets[8..16].copy_from_slice(&iid);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eui64_flips_universal_local_bit_and_inserts_fffe() {
        // Well-known textbook example: MAC 00:0C:29:AA:BB:CC.
        let mac = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];
        let iid = eui64_iid(mac);
        assert_eq!(iid, [0x02, 0x0c, 0x29, 0xff, 0xfe, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn eui64_address_combines_prefix_and_iid() {
        let mac = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let addr = make_address(prefix, eui64_iid(mac));
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0x020c, 0x29ff, 0xfeaa, 0xbbcc));
    }

    #[test]
    fn rfc7217_is_deterministic_for_the_same_inputs() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let a = rfc7217_iid(prefix, b"eth0", b"", 0, b"secret");
        let b = rfc7217_iid(prefix, b"eth0", b"", 0, b"secret");
        assert_eq!(a, b);
    }

    #[test]
    fn rfc7217_differs_when_any_input_differs() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let other_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0);
        let base = rfc7217_iid(prefix, b"eth0", b"", 0, b"secret");

        assert_ne!(base, rfc7217_iid(other_prefix, b"eth0", b"", 0, b"secret"));
        assert_ne!(base, rfc7217_iid(prefix, b"eth1", b"", 0, b"secret"));
        assert_ne!(base, rfc7217_iid(prefix, b"eth0", b"ssid", 0, b"secret"));
        assert_ne!(base, rfc7217_iid(prefix, b"eth0", b"", 1, b"secret"));
        assert_ne!(base, rfc7217_iid(prefix, b"eth0", b"", 0, b"other-secret"));
    }

    #[test]
    fn reserved_iids_are_flagged() {
        assert!(is_reserved_iid(&[0u8; 8]));
        assert!(is_reserved_iid(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]));
        assert!(is_reserved_iid(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
        assert!(!is_reserved_iid(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]));
        assert!(!is_reserved_iid(&eui64_iid([0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc])));
    }
}
