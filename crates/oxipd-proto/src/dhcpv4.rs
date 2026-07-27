//! DHCPv4 / BOOTP message codec (RFC 951, RFC 2131, RFC 2132, RFC 3396).
//!
//! `Message` is a zero-copy *view* over a received packet buffer: header
//! fields are read directly out of the borrowed slice, and options are
//! walked on demand rather than eagerly parsed into an owned structure. Two
//! wire-format subtleties are handled transparently by the options walker
//! because getting them wrong silently breaks interop with real DHCP
//! servers:
//!
//! - **Option overload** (RFC 2132 §9.3, option 52): when set, the `file`
//!   and/or `sname` header fields are reinterpreted as extra option space
//!   appended after the primary `options` area.
//! - **RFC 3396 long options**: an option value longer than 255 bytes is
//!   sent as consecutive TLV entries sharing the same code; a reader must
//!   concatenate them back into one logical value.
//!
//! `MessageBuilder` is the write side: it accepts logical (code, full-length
//! value) pairs and performs the RFC 3396 chunking itself.

use std::net::Ipv4Addr;

/// DHCP magic cookie that begins the options area (RFC 2131 §3).
pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Length of the fixed BOOTP header, i.e. the byte offset at which the
/// magic cookie / options area begins.
pub const FIXED_LEN: usize = 236;
/// Length of the `chaddr` field.
pub const CHADDR_LEN: usize = 16;
/// Length of the `sname` field.
pub const SNAME_LEN: usize = 64;
/// Length of the `file` field.
pub const FILE_LEN: usize = 128;

/// `sizeof(struct bootp)` in the reference implementation: fixed header +
/// cookie + at least the classic 64-byte vendor area. Padding outbound
/// messages up to this size is RFC 1542 §2.1 hygiene for BOOTP relay agents
/// that assume a minimum packet size; [`MessageBuilder::build`] does this by
/// default.
pub const MIN_MESSAGE_LEN: usize = FIXED_LEN + 64;

/// Minimum a buffer must be to plausibly be a DHCP/BOOTP message at all
/// (fixed header + magic cookie, no options).
pub const DHCP_MIN_LEN: usize = FIXED_LEN + 4;

// --- BOOTP `op` values (RFC 951) -------------------------------------------------
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

// --- Well-known DHCP option codes (subset actually acted on by oxipd-core) -------
pub mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DNS_DOMAIN: u8 = 15;
    pub const MTU: u8 = 26;
    pub const BROADCAST: u8 = 28;
    pub const STATIC_ROUTE: u8 = 33;
    pub const NIS_DOMAIN: u8 = 40;
    pub const NIS_SERVER: u8 = 41;
    pub const NTP_SERVER: u8 = 42;
    pub const VENDOR: u8 = 43;
    pub const REQUESTED_IP_ADDRESS: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const OPTION_OVERLOAD: u8 = 52;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_IDENTIFIER: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MESSAGE: u8 = 56;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_IDENTIFIER: u8 = 61;
    pub const USER_CLASS: u8 = 77;
    pub const RAPID_COMMIT: u8 = 80;
    pub const FQDN: u8 = 81;
    pub const AUTHENTICATION: u8 = 90;
    pub const IPV6_ONLY_PREFERRED: u8 = 108;
    pub const AUTO_CONFIGURE: u8 = 116;
    pub const DNS_SEARCH: u8 = 119;
    pub const CLASSLESS_STATIC_ROUTE: u8 = 121;
    pub const VIVCO: u8 = 124;
    pub const VIVSO: u8 = 125;
    pub const FORCERENEW_NONCE: u8 = 145;
    pub const MUD_URL: u8 = 161;
    pub const SIXRD: u8 = 212;
    pub const MS_CLASSLESS_STATIC_ROUTE: u8 = 249;
    pub const END: u8 = 255;
}

/// DHCP message type (option 53 payload, RFC 2131 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    ForceRenew = 9,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Error> {
        Ok(match v {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            8 => MessageType::Inform,
            9 => MessageType::ForceRenew,
            other => return Err(Error::UnknownMessageType(other)),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short to be a DHCP message: {0} bytes")]
    TooShort(usize),
    #[error("missing or invalid DHCP magic cookie")]
    BadCookie,
    #[error("unknown DHCP message type: {0}")]
    UnknownMessageType(u8),
    #[error("message has no DHCP message type option (option 53)")]
    NoMessageType,
}

/// A borrowed, zero-copy view over a raw DHCPv4/BOOTP packet.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    buf: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse `buf` as a DHCP message: validates minimum length and the
    /// magic cookie. Does not validate that the option area itself is
    /// well-formed; malformed trailing options are silently truncated when
    /// walked (matching the reference client's tolerant behavior toward
    /// real-world broken servers, but never panicking or reading OOB).
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < DHCP_MIN_LEN {
            return Err(Error::TooShort(buf.len()));
        }
        if buf[FIXED_LEN..FIXED_LEN + 4] != MAGIC_COOKIE {
            return Err(Error::BadCookie);
        }
        Ok(Message { buf })
    }

    /// Parse as plain BOOTP: only requires the fixed header, no magic
    /// cookie / options area at all (used for `--bootp` legacy mode).
    pub fn parse_bootp(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < FIXED_LEN {
            return Err(Error::TooShort(buf.len()));
        }
        Ok(Message { buf })
    }

    pub fn op(&self) -> u8 {
        self.buf[0]
    }
    pub fn htype(&self) -> u8 {
        self.buf[1]
    }
    pub fn hlen(&self) -> u8 {
        self.buf[2]
    }
    pub fn hops(&self) -> u8 {
        self.buf[3]
    }
    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.buf[4..8].try_into().unwrap())
    }
    pub fn secs(&self) -> u16 {
        u16::from_be_bytes(self.buf[8..10].try_into().unwrap())
    }
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes(self.buf[10..12].try_into().unwrap())
    }
    pub fn broadcast(&self) -> bool {
        self.flags() & 0x8000 != 0
    }
    pub fn ciaddr(&self) -> Ipv4Addr {
        addr_at(self.buf, 12)
    }
    pub fn yiaddr(&self) -> Ipv4Addr {
        addr_at(self.buf, 16)
    }
    pub fn siaddr(&self) -> Ipv4Addr {
        addr_at(self.buf, 20)
    }
    pub fn giaddr(&self) -> Ipv4Addr {
        addr_at(self.buf, 24)
    }
    /// Raw hardware address bytes; only the first `hlen` bytes are meaningful.
    pub fn chaddr(&self) -> &'a [u8] {
        &self.buf[28..28 + CHADDR_LEN]
    }

    fn sname_raw(&self) -> &'a [u8] {
        &self.buf[28 + CHADDR_LEN..28 + CHADDR_LEN + SNAME_LEN]
    }
    fn file_raw(&self) -> &'a [u8] {
        &self.buf[28 + CHADDR_LEN + SNAME_LEN..FIXED_LEN]
    }
    fn vend_raw(&self) -> &'a [u8] {
        if self.buf.len() <= FIXED_LEN + 4 {
            &[]
        } else {
            &self.buf[FIXED_LEN + 4..]
        }
    }

    /// True if this buffer carries the DHCP magic cookie (as opposed to
    /// being plain BOOTP with no options area at all).
    pub fn is_dhcp(&self) -> bool {
        self.buf.len() >= FIXED_LEN + 4 && self.buf[FIXED_LEN..FIXED_LEN + 4] == MAGIC_COOKIE
    }

    /// The option-overload flag (option 52), 0 if absent. Requires one
    /// linear scan of just the primary options area.
    fn overload(&self) -> u8 {
        for (code, data) in RawOptions::new(self.vend_raw()) {
            if code == opt::OPTION_OVERLOAD {
                return data.first().copied().unwrap_or(0);
            }
        }
        0
    }

    /// Iterate over every option, with RFC 3396 same-code runs and RFC 2132
    /// option-overload areas transparently merged into one logical value
    /// per code, in order of first appearance.
    pub fn options(&self) -> Options {
        let overload = self.overload();
        let mut areas = [self.vend_raw(), &[][..], &[][..]];
        let mut n = 1;
        // RFC 2132 order: options, then file (if bit 0 set), then sname (if bit 1 set).
        if overload & 0x1 != 0 {
            areas[n] = self.file_raw();
            n += 1;
        }
        if overload & 0x2 != 0 {
            areas[n] = self.sname_raw();
            n += 1;
        }
        Options {
            merged: merge_options(areas, n),
            pos: 0,
        }
    }

    /// Look up a single option's fully-concatenated value.
    pub fn option(&self, code: u8) -> Option<Vec<u8>> {
        self.options().find(|(c, _)| *c == code).map(|(_, v)| v)
    }

    pub fn message_type(&self) -> Result<MessageType, Error> {
        let raw = self.option(opt::MESSAGE_TYPE).ok_or(Error::NoMessageType)?;
        let byte = *raw.first().ok_or(Error::NoMessageType)?;
        MessageType::try_from(byte)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.buf
    }
}

fn addr_at(buf: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3])
}

/// Walks a single raw TLV area (no overload/RFC3396 awareness), stopping at
/// `END`, a truncated trailing TLV, or the end of the buffer. `PAD` bytes
/// are skipped. Never panics on malformed input.
struct RawOptions<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> RawOptions<'a> {
    fn new(buf: &'a [u8]) -> Self {
        RawOptions {
            buf,
            pos: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for RawOptions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done || self.pos >= self.buf.len() {
                return None;
            }
            let code = self.buf[self.pos];
            if code == opt::PAD {
                self.pos += 1;
                continue;
            }
            if code == opt::END {
                self.done = true;
                return None;
            }
            if self.pos + 1 >= self.buf.len() {
                self.done = true; // truncated length byte
                return None;
            }
            let len = self.buf[self.pos + 1] as usize;
            let start = self.pos + 2;
            let end = start + len;
            if end > self.buf.len() {
                self.done = true; // truncated value
                return None;
            }
            self.pos = end;
            return Some((code, &self.buf[start..end]));
        }
    }
}

/// Merge (in first-appearance order) every RFC-3396 same-code run, across
/// up to 3 option areas (options/file/sname), into one owned buffer per code.
fn merge_options(areas: [&[u8]; 3], n: usize) -> Vec<(u8, Vec<u8>)> {
    let mut merged: Vec<(u8, Vec<u8>)> = Vec::new();
    for area in areas.iter().take(n) {
        for (code, data) in RawOptions::new(area) {
            if let Some(entry) = merged.iter_mut().find(|(c, _)| *c == code) {
                entry.1.extend_from_slice(data);
            } else {
                merged.push((code, data.to_vec()));
            }
        }
    }
    merged
}

/// Iterator over an already-merged option list. Fully owned (the merge
/// step already copies option bytes out of the source buffer), so it has
/// no borrow relationship to the `Message` it was built from.
pub struct Options {
    merged: Vec<(u8, Vec<u8>)>,
    pos: usize,
}

impl Iterator for Options {
    type Item = (u8, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.merged.len() {
            return None;
        }
        let item = self.merged[self.pos].clone();
        self.pos += 1;
        Some(item)
    }
}

/// Builds a DHCPv4 message from typed fields. Performs RFC 3396 chunking of
/// any option value over 255 bytes automatically.
pub struct MessageBuilder {
    op: u8,
    htype: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; CHADDR_LEN],
    hlen: u8,
    options: Vec<(u8, Vec<u8>)>,
    pad_to: usize,
}

impl MessageBuilder {
    pub fn new(op: u8, xid: u32) -> Self {
        MessageBuilder {
            op,
            htype: 1, // ARPHRD_ETHER
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; CHADDR_LEN],
            hlen: 0,
            options: Vec::new(),
            pad_to: MIN_MESSAGE_LEN,
        }
    }

    pub fn secs(&mut self, v: u16) -> &mut Self {
        self.secs = v;
        self
    }
    pub fn broadcast_flag(&mut self, v: bool) -> &mut Self {
        self.flags = if v { self.flags | 0x8000 } else { self.flags & !0x8000 };
        self
    }
    pub fn ciaddr(&mut self, v: Ipv4Addr) -> &mut Self {
        self.ciaddr = v;
        self
    }
    pub fn chaddr(&mut self, mac: &[u8]) -> &mut Self {
        self.hlen = mac.len().min(CHADDR_LEN) as u8;
        self.chaddr = [0; CHADDR_LEN];
        self.chaddr[..self.hlen as usize].copy_from_slice(&mac[..self.hlen as usize]);
        self
    }
    pub fn message_type(&mut self, t: MessageType) -> &mut Self {
        self.add_option(opt::MESSAGE_TYPE, &[t as u8])
    }
    /// Skip the RFC1542 minimum-size padding (only useful for tests that
    /// want to see the exact minimal encoding).
    pub fn no_min_padding(&mut self) -> &mut Self {
        self.pad_to = 0;
        self
    }
    pub fn add_option(&mut self, code: u8, data: &[u8]) -> &mut Self {
        self.options.push((code, data.to_vec()));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MIN_MESSAGE_LEN);
        buf.push(self.op);
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.resize(buf.len() + SNAME_LEN, 0);
        buf.resize(buf.len() + FILE_LEN, 0);
        debug_assert_eq!(buf.len(), FIXED_LEN);
        buf.extend_from_slice(&MAGIC_COOKIE);
        for (code, data) in &self.options {
            write_option_rfc3396(&mut buf, *code, data);
        }
        buf.push(opt::END);
        if buf.len() < self.pad_to {
            buf.resize(self.pad_to, opt::PAD);
        }
        buf
    }
}

fn write_option_rfc3396(buf: &mut Vec<u8>, code: u8, data: &[u8]) {
    if data.is_empty() {
        buf.push(code);
        buf.push(0);
        return;
    }
    for chunk in data.chunks(255) {
        buf.push(code);
        buf.push(chunk.len() as u8);
        buf.extend_from_slice(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chaddr() -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    }

    #[test]
    fn round_trip_discover() {
        let mac = sample_chaddr();
        let mut b = MessageBuilder::new(BOOTREQUEST, 0xdead_beef);
        b.chaddr(&mac)
            .secs(3)
            .broadcast_flag(true)
            .message_type(MessageType::Discover)
            .add_option(opt::PARAMETER_REQUEST_LIST, &[opt::SUBNET_MASK, opt::ROUTER, opt::DNS_SERVER]);
        let bytes = b.build();

        assert!(bytes.len() >= MIN_MESSAGE_LEN);

        let msg = Message::parse(&bytes).expect("parses");
        assert_eq!(msg.op(), BOOTREQUEST);
        assert_eq!(msg.xid(), 0xdead_beef);
        assert_eq!(msg.secs(), 3);
        assert!(msg.broadcast());
        assert_eq!(msg.hlen(), 6);
        assert_eq!(&msg.chaddr()[..6], &mac[..]);
        assert!(msg.is_dhcp());
        assert_eq!(msg.message_type().unwrap(), MessageType::Discover);
        assert_eq!(
            msg.option(opt::PARAMETER_REQUEST_LIST).unwrap(),
            vec![opt::SUBNET_MASK, opt::ROUTER, opt::DNS_SERVER]
        );
    }

    #[test]
    fn too_short_is_rejected() {
        let bytes = vec![0u8; 10];
        assert_eq!(Message::parse(&bytes).unwrap_err(), Error::TooShort(10));
    }

    #[test]
    fn bad_cookie_is_rejected() {
        let mut bytes = vec![0u8; DHCP_MIN_LEN];
        bytes[FIXED_LEN..FIXED_LEN + 4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(Message::parse(&bytes).unwrap_err(), Error::BadCookie);
    }

    #[test]
    fn rfc3396_long_option_is_concatenated_on_read() {
        let mut b = MessageBuilder::new(BOOTREQUEST, 1);
        // 300-byte value forces the builder to split into two chunks (255 + 45).
        let long_value: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();
        b.add_option(opt::VENDOR_CLASS_ID, &long_value);
        let bytes = b.build();

        let msg = Message::parse(&bytes).unwrap();
        let round_tripped = msg.option(opt::VENDOR_CLASS_ID).unwrap();
        assert_eq!(round_tripped, long_value);
    }

    #[test]
    fn option_overload_file_and_sname_are_scanned() {
        // Hand-build a message: primary options area only contains the
        // overload flag (both file+sname carry options) plus END; the
        // "extra" options live directly in the file/sname fields.
        let mut buf = vec![0u8; FIXED_LEN];
        buf[0] = BOOTREQUEST;
        buf.extend_from_slice(&MAGIC_COOKIE);
        // primary options area: OPTION_OVERLOAD=3 (file+sname), then END.
        buf.push(opt::OPTION_OVERLOAD);
        buf.push(1);
        buf.push(3);
        buf.push(opt::END);

        // Now go back and stuff option 60 (vendor-class) into `file` and
        // option 12 (hostname) into `sname`, per RFC2132 order: file first.
        let file_off = 28 + CHADDR_LEN + SNAME_LEN;
        buf[file_off] = opt::VENDOR_CLASS_ID;
        buf[file_off + 1] = 3;
        buf[file_off + 2..file_off + 5].copy_from_slice(b"abc");
        buf[file_off + 5] = opt::END;

        let sname_off = 28 + CHADDR_LEN;
        buf[sname_off] = opt::HOSTNAME;
        buf[sname_off + 1] = 4;
        buf[sname_off + 2..sname_off + 6].copy_from_slice(b"host");
        buf[sname_off + 6] = opt::END;

        let msg = Message::parse(&buf).expect("valid dhcp message");
        assert_eq!(msg.option(opt::VENDOR_CLASS_ID).unwrap(), b"abc".to_vec());
        assert_eq!(msg.option(opt::HOSTNAME).unwrap(), b"host".to_vec());
    }

    #[test]
    fn malformed_trailing_option_does_not_panic() {
        let mut buf = vec![0u8; FIXED_LEN];
        buf[0] = BOOTREQUEST;
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.push(opt::HOSTNAME);
        buf.push(10); // claims 10 bytes but buffer ends here
        let msg = Message::parse(&buf).expect("still parses header");
        assert_eq!(msg.option(opt::HOSTNAME), None);
        assert_eq!(msg.options().count(), 0);
    }
}
