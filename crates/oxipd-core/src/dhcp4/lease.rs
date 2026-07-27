//! Extracting a [`Lease`] from a parsed DHCPACK — the typed view of the
//! handful of options oxipd-core's state machine and interface manager
//! actually act on, out of the raw option bag `oxipd_proto::dhcpv4`
//! exposes.

use std::net::Ipv4Addr;

use oxipd_proto::dhcpv4::{opt, Message};

use super::timing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub your_addr: Ipv4Addr,
    pub server_addr: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    /// Seconds, or `u32::MAX` for RFC 2131's infinite lease.
    pub lease_time: u32,
    /// T1, seconds (see [`timing::compute_t1_t2`]).
    pub renewal_time: u32,
    /// T2, seconds.
    pub rebinding_time: u32,
}

impl Lease {
    /// Build a `Lease` from a received DHCPACK (or a saved/reloaded lease
    /// re-encoded the same way). Missing option 51 (lease time) is
    /// treated as infinite, matching how an absent lease time is commonly
    /// handled in practice (RFC 2131 doesn't actually allow servers to
    /// omit it, but plenty do for static/BOOTP-ish assignments).
    pub fn from_message(msg: &Message) -> Self {
        let your_addr = msg.yiaddr();

        let mut server_addr = None;
        let mut subnet_mask = None;
        let mut broadcast = None;
        let mut routers = Vec::new();
        let mut dns_servers = Vec::new();
        let mut domain_name = None;
        let mut lease_time = None;
        let mut server_t1 = None;
        let mut server_t2 = None;

        for (code, data) in msg.options() {
            match code {
                opt::SUBNET_MASK => subnet_mask = ipv4(&data),
                opt::ROUTER => routers = ipv4_list(&data),
                opt::DNS_SERVER => dns_servers = ipv4_list(&data),
                opt::DNS_DOMAIN => domain_name = String::from_utf8(data).ok(),
                opt::BROADCAST => broadcast = ipv4(&data),
                opt::LEASE_TIME => lease_time = u32_be(&data),
                opt::SERVER_IDENTIFIER => server_addr = ipv4(&data),
                opt::RENEWAL_TIME => server_t1 = u32_be(&data),
                opt::REBINDING_TIME => server_t2 = u32_be(&data),
                _ => {}
            }
        }

        let lease_time = lease_time.unwrap_or(u32::MAX).max(timing::MIN_LEASE_SECS);
        let (renewal_time, rebinding_time) = timing::compute_t1_t2(lease_time, server_t1, server_t2);

        Lease {
            your_addr,
            server_addr,
            subnet_mask,
            broadcast,
            routers,
            dns_servers,
            domain_name,
            lease_time,
            renewal_time,
            rebinding_time,
        }
    }
}

fn ipv4(data: &[u8]) -> Option<Ipv4Addr> {
    (data.len() >= 4).then(|| Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn ipv4_list(data: &[u8]) -> Vec<Ipv4Addr> {
    data.chunks_exact(4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect()
}

fn u32_be(data: &[u8]) -> Option<u32> {
    (data.len() >= 4).then(|| u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxipd_proto::dhcpv4::{MessageBuilder, MessageType, BOOTREPLY};

    fn sample_ack(lease_secs: u32) -> Vec<u8> {
        let mut b = MessageBuilder::new(BOOTREPLY, 42);
        b.message_type(MessageType::Ack)
            .add_option(opt::SUBNET_MASK, &Ipv4Addr::new(255, 255, 255, 0).octets())
            .add_option(opt::ROUTER, &Ipv4Addr::new(192, 168, 1, 1).octets())
            .add_option(opt::DNS_SERVER, &[
                Ipv4Addr::new(8, 8, 8, 8).octets(),
                Ipv4Addr::new(8, 8, 4, 4).octets(),
            ].concat())
            .add_option(opt::LEASE_TIME, &lease_secs.to_be_bytes())
            .add_option(opt::SERVER_IDENTIFIER, &Ipv4Addr::new(192, 168, 1, 1).octets());
        b.build()
    }

    #[test]
    fn extracts_the_common_fields() {
        let bytes = sample_ack(3600);
        let msg = Message::parse(&bytes).unwrap();
        let lease = Lease::from_message(&msg);

        assert_eq!(lease.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(lease.routers, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(lease.dns_servers, vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]);
        assert_eq!(lease.server_addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(lease.lease_time, 3600);
        assert_eq!(lease.renewal_time, 1800);
        assert_eq!(lease.rebinding_time, 3150);
    }

    #[test]
    fn missing_lease_time_is_treated_as_infinite() {
        let mut b = MessageBuilder::new(BOOTREPLY, 1);
        b.message_type(MessageType::Ack);
        let bytes = b.build();
        let msg = Message::parse(&bytes).unwrap();
        let lease = Lease::from_message(&msg);
        assert_eq!(lease.lease_time, u32::MAX);
        assert_eq!(lease.renewal_time, u32::MAX);
    }

    #[test]
    fn tiny_lease_time_is_clamped_to_the_floor() {
        let bytes = sample_ack(1);
        let msg = Message::parse(&bytes).unwrap();
        let lease = Lease::from_message(&msg);
        assert_eq!(lease.lease_time, timing::MIN_LEASE_SECS);
    }
}
