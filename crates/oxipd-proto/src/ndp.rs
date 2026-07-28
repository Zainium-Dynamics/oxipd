//! ICMPv6 Neighbor Discovery Protocol codec (RFC 4861 Router
//! Solicitation/Advertisement + options, RFC 4191 Route Information, RFC
//! 8106 RDNSS) — the wire format `oxipd_core::ipv6nd`'s RA-processing/
//! SLAAC engine consumes. oxipd only ever *builds* Router Solicitations
//! and *parses* Router Advertisements (it never acts as a router), so
//! there's no `RouterAdvertisement` builder — only a parser.

use std::net::Ipv6Addr;

pub const ICMP6_ROUTER_SOLICIT: u8 = 133;
pub const ICMP6_ROUTER_ADVERT: u8 = 134;

/// icmp6_hdr (4 bytes: type/code/checksum) + RS body (4-byte reserved).
pub const RS_FIXED_LEN: usize = 8;
/// icmp6_hdr (4 bytes) + RA body (12 bytes: hop limit/flags/lifetime/
/// reachable-time/retrans-timer).
pub const RA_FIXED_LEN: usize = 16;

pub const OPT_SOURCE_LL_ADDR: u8 = 1;
pub const OPT_TARGET_LL_ADDR: u8 = 2;
pub const OPT_PREFIX_INFORMATION: u8 = 3;
pub const OPT_MTU: u8 = 5;
pub const OPT_ROUTE_INFORMATION: u8 = 24;
pub const OPT_RDNSS: u8 = 25;

/// Build a Router Solicitation, optionally carrying a Source Link-Layer
/// Address option. ICMPv6 checksum is left as the wire's zero placeholder
/// — it depends on the IPv6 pseudo-header (source/destination address),
/// which only the caller sending the packet knows; fill it in with
/// `oxipd_net::checksum::icmp6_checksum_v6` before transmitting.
pub fn build_router_solicitation(source_ll_addr: Option<&[u8; 6]>) -> Vec<u8> {
    let mut buf = vec![0u8; RS_FIXED_LEN];
    buf[0] = ICMP6_ROUTER_SOLICIT;
    if let Some(addr) = source_ll_addr {
        buf.push(OPT_SOURCE_LL_ADDR);
        buf.push(1); // length in 8-byte units: 2 (type+len) + 6 (addr) = 8
        buf.extend_from_slice(addr);
    }
    buf
}

/// A borrowed, zero-copy view over a received Router Advertisement.
#[derive(Debug, Clone, Copy)]
pub struct RouterAdvertisement<'a> {
    buf: &'a [u8],
}

impl<'a> RouterAdvertisement<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < RA_FIXED_LEN || buf[0] != ICMP6_ROUTER_ADVERT {
            return None;
        }
        Some(RouterAdvertisement { buf })
    }

    pub fn cur_hop_limit(&self) -> u8 {
        self.buf[4]
    }
    /// The 'M' (Managed) flag: hosts should use stateful DHCPv6.
    pub fn managed(&self) -> bool {
        self.buf[5] & 0x80 != 0
    }
    /// The 'O' (Other) flag: hosts should use stateless DHCPv6 for
    /// options only (no address assignment).
    pub fn other_config(&self) -> bool {
        self.buf[5] & 0x40 != 0
    }
    /// RFC 4191 default router preference: `1` = High, `0` = Medium
    /// (default/unset), `-1` = Low.
    pub fn default_preference(&self) -> i8 {
        decode_preference(self.buf[5] >> 3)
    }
    pub fn router_lifetime_secs(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }
    pub fn reachable_time_ms(&self) -> u32 {
        u32::from_be_bytes(self.buf[8..12].try_into().unwrap())
    }
    pub fn retrans_timer_ms(&self) -> u32 {
        u32::from_be_bytes(self.buf[12..16].try_into().unwrap())
    }

    pub fn options(&self) -> NdpOptions<'a> {
        NdpOptions::new(&self.buf[RA_FIXED_LEN..])
    }
}

fn decode_preference(bits: u8) -> i8 {
    match bits & 0x3 {
        0b01 => 1,
        0b11 => -1,
        _ => 0, // 0b00 Medium, 0b10 reserved (treated as Medium)
    }
}

/// Walks the 8-byte-unit-length TLV options following a fixed ND message
/// header. Stops (without panicking) on a truncated or zero-length
/// option, since a zero length would otherwise loop forever.
pub struct NdpOptions<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> NdpOptions<'a> {
    fn new(buf: &'a [u8]) -> Self {
        NdpOptions { buf, pos: 0, done: false }
    }
}

impl<'a> Iterator for NdpOptions<'a> {
    /// `(option_type, value)` where `value` is everything after the
    /// 2-byte type+length header (i.e. `(length_units * 8) - 2` bytes).
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos + 2 > self.buf.len() {
            return None;
        }
        let otype = self.buf[self.pos];
        let len_units = self.buf[self.pos + 1];
        if len_units == 0 {
            self.done = true;
            return None;
        }
        let total_len = len_units as usize * 8;
        if self.pos + total_len > self.buf.len() {
            self.done = true;
            return None;
        }
        let value = &self.buf[self.pos + 2..self.pos + total_len];
        self.pos += total_len;
        Some((otype, value))
    }
}

/// RFC 4861 §4.6.2 Prefix Information option (SLAAC + on-link prefixes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix_len: u8,
    /// 'L' bit: this prefix is on-link.
    pub on_link: bool,
    /// 'A' bit: usable for stateless address autoconfiguration.
    pub autonomous: bool,
    pub valid_lifetime_secs: u32,
    pub preferred_lifetime_secs: u32,
    pub prefix: Ipv6Addr,
}

impl PrefixInformation {
    /// `value` is an [`NdpOptions`] item's value (after type+length).
    pub fn parse(value: &[u8]) -> Option<Self> {
        // prefix_len(1) flags(1) valid(4) preferred(4) reserved2(4) prefix(16) = 30
        if value.len() < 30 {
            return None;
        }
        let flags = value[1];
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&value[14..30]);
        Some(PrefixInformation {
            prefix_len: value[0],
            on_link: flags & 0x80 != 0,
            autonomous: flags & 0x40 != 0,
            valid_lifetime_secs: u32::from_be_bytes(value[2..6].try_into().unwrap()),
            preferred_lifetime_secs: u32::from_be_bytes(value[6..10].try_into().unwrap()),
            prefix: Ipv6Addr::from(octets),
        })
    }
}

/// RFC 4861 §4.6.4 MTU option.
pub fn parse_mtu(value: &[u8]) -> Option<u32> {
    // reserved(2) mtu(4) = 6
    (value.len() >= 6).then(|| u32::from_be_bytes(value[2..6].try_into().unwrap()))
}

/// RFC 4191 Route Information option. The on-wire prefix is 0, 8, or 16
/// bytes depending on `prefix_len`; `prefix` is always zero-padded out to
/// a full address here for a uniform type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInformation {
    pub prefix_len: u8,
    /// RFC 4191 route preference: `1` High, `0` Medium, `-1` Low.
    pub preference: i8,
    pub route_lifetime_secs: u32,
    pub prefix: Ipv6Addr,
}

impl RouteInformation {
    pub fn parse(value: &[u8]) -> Option<Self> {
        // prefix_len(1) flags(1) lifetime(4) [+ 0/8/16 bytes of prefix]
        if value.len() < 6 {
            return None;
        }
        let flags = value[1];
        let prefix_bytes = &value[6..];
        let mut octets = [0u8; 16];
        let n = prefix_bytes.len().min(16);
        octets[..n].copy_from_slice(&prefix_bytes[..n]);
        Some(RouteInformation {
            prefix_len: value[0],
            preference: decode_preference(flags >> 3),
            route_lifetime_secs: u32::from_be_bytes(value[2..6].try_into().unwrap()),
            prefix: Ipv6Addr::from(octets),
        })
    }
}

/// RFC 8106 Recursive DNS Server option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdnss {
    pub lifetime_secs: u32,
    pub servers: Vec<Ipv6Addr>,
}

impl Rdnss {
    pub fn parse(value: &[u8]) -> Option<Self> {
        // reserved(2) lifetime(4) [+ N * 16-byte addresses]
        if value.len() < 6 {
            return None;
        }
        let lifetime_secs = u32::from_be_bytes(value[2..6].try_into().unwrap());
        let servers = value[6..]
            .chunks_exact(16)
            .map(|c| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(c);
                Ipv6Addr::from(octets)
            })
            .collect();
        Some(Rdnss { lifetime_secs, servers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_option(buf: &mut Vec<u8>, otype: u8, value: &[u8]) {
        let total = 2 + value.len();
        assert_eq!(total % 8, 0, "test fixture option not 8-byte aligned");
        buf.push(otype);
        buf.push((total / 8) as u8);
        buf.extend_from_slice(value);
    }

    fn sample_ra(flags: u8) -> Vec<u8> {
        let mut buf = vec![0u8; RA_FIXED_LEN];
        buf[0] = ICMP6_ROUTER_ADVERT;
        buf[4] = 64; // cur hop limit
        buf[5] = flags;
        buf[6..8].copy_from_slice(&1800u16.to_be_bytes()); // router lifetime
        buf[8..12].copy_from_slice(&30000u32.to_be_bytes()); // reachable time
        buf[12..16].copy_from_slice(&1000u32.to_be_bytes()); // retrans timer
        buf
    }

    #[test]
    fn router_solicitation_has_no_options_when_none_requested() {
        let bytes = build_router_solicitation(None);
        assert_eq!(bytes.len(), RS_FIXED_LEN);
        assert_eq!(bytes[0], ICMP6_ROUTER_SOLICIT);
    }

    #[test]
    fn router_solicitation_carries_source_ll_addr() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bytes = build_router_solicitation(Some(&mac));
        assert_eq!(bytes.len(), RS_FIXED_LEN + 8);
        let opts: Vec<_> = NdpOptions::new(&bytes[RS_FIXED_LEN..]).collect();
        assert_eq!(opts, vec![(OPT_SOURCE_LL_ADDR, &mac[..])]);
    }

    #[test]
    fn ra_header_fields_and_mo_flags() {
        let bytes = sample_ra(0x80); // M set, O clear
        let ra = RouterAdvertisement::parse(&bytes).unwrap();
        assert_eq!(ra.cur_hop_limit(), 64);
        assert!(ra.managed());
        assert!(!ra.other_config());
        assert_eq!(ra.router_lifetime_secs(), 1800);
        assert_eq!(ra.reachable_time_ms(), 30000);
        assert_eq!(ra.retrans_timer_ms(), 1000);
        assert_eq!(ra.options().count(), 0);

        let bytes = sample_ra(0x40); // O set, M clear
        let ra = RouterAdvertisement::parse(&bytes).unwrap();
        assert!(!ra.managed());
        assert!(ra.other_config());
    }

    #[test]
    fn ra_with_prefix_information_and_mtu_and_rdnss() {
        let mut bytes = sample_ra(0);

        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        let mut pio = vec![64u8, 0xC0]; // prefix_len=64, L+A set
        pio.extend_from_slice(&86400u32.to_be_bytes()); // valid
        pio.extend_from_slice(&14400u32.to_be_bytes()); // preferred
        pio.extend_from_slice(&[0u8; 4]); // reserved2
        pio.extend_from_slice(&prefix.octets());
        push_option(&mut bytes, OPT_PREFIX_INFORMATION, &pio);

        let mut mtu_val = vec![0u8; 2];
        mtu_val.extend_from_slice(&1500u32.to_be_bytes());
        push_option(&mut bytes, OPT_MTU, &mtu_val);

        let dns1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut rdnss_val = vec![0u8; 2];
        rdnss_val.extend_from_slice(&600u32.to_be_bytes());
        rdnss_val.extend_from_slice(&dns1.octets());
        push_option(&mut bytes, OPT_RDNSS, &rdnss_val);

        let ra = RouterAdvertisement::parse(&bytes).unwrap();
        let opts: Vec<_> = ra.options().collect();
        assert_eq!(opts.len(), 3);

        let pio = PrefixInformation::parse(opts[0].1).unwrap();
        assert_eq!(pio.prefix_len, 64);
        assert!(pio.on_link);
        assert!(pio.autonomous);
        assert_eq!(pio.valid_lifetime_secs, 86400);
        assert_eq!(pio.preferred_lifetime_secs, 14400);
        assert_eq!(pio.prefix, prefix);

        assert_eq!(parse_mtu(opts[1].1), Some(1500));

        let rdnss = Rdnss::parse(opts[2].1).unwrap();
        assert_eq!(rdnss.lifetime_secs, 600);
        assert_eq!(rdnss.servers, vec![dns1]);
    }

    #[test]
    fn route_information_decodes_preference_and_variable_prefix_len() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0);
        let mut value = vec![48u8, 0b0000_1000]; // prefix_len=48, preference=High (01)
        value.extend_from_slice(&3600u32.to_be_bytes());
        value.extend_from_slice(&prefix.octets()[..8]); // 48-bit prefix -> 8 bytes on wire

        let ri = RouteInformation::parse(&value).unwrap();
        assert_eq!(ri.prefix_len, 48);
        assert_eq!(ri.preference, 1);
        assert_eq!(ri.route_lifetime_secs, 3600);
        // Zero-padded out to a full address for the unified type.
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&prefix.octets()[..8]);
        assert_eq!(ri.prefix, Ipv6Addr::from(expected));
    }

    #[test]
    fn zero_length_option_stops_iteration_without_looping() {
        let mut bytes = sample_ra(0);
        bytes.push(OPT_MTU);
        bytes.push(0); // malformed: zero length
        bytes.extend_from_slice(&[0u8; 6]);
        let ra = RouterAdvertisement::parse(&bytes).unwrap();
        assert_eq!(ra.options().count(), 0);
    }

    #[test]
    fn truncated_option_does_not_panic() {
        let mut bytes = sample_ra(0);
        bytes.push(OPT_PREFIX_INFORMATION);
        bytes.push(4); // claims 32 bytes but buffer ends here
        let ra = RouterAdvertisement::parse(&bytes).unwrap();
        assert_eq!(ra.options().count(), 0);
    }

    #[test]
    fn wrong_message_type_is_rejected() {
        let mut bytes = sample_ra(0);
        bytes[0] = ICMP6_ROUTER_SOLICIT;
        assert!(RouterAdvertisement::parse(&bytes).is_none());
    }
}
