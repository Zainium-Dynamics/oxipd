//! Manual runtime check for the M4 async shell (`Ipv6NdClient`): opens a
//! raw ICMPv6 socket directly (no privsep wiring yet), solicits and
//! processes Router Advertisements on a real interface for up to 15s.
//!
//! Requires `CAP_NET_RAW`/root, and a real IPv6 router advertising on the
//! given interface to see any prefixes. Run with:
//! `cargo run -p oxipd-core --example ipv6nd_client -- <ifname>`

use oxipd_core::ipv6nd::{IidScheme, Ipv6NdClient};
use oxipd_net::icmp6::RawIcmp6Socket;
use oxipd_net::netlink::NetlinkClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let ifname = std::env::args()
        .nth(1)
        .ok_or("usage: ipv6nd_client <ifname>")?;

    let (netlink, events) = NetlinkClient::spawn()?;
    let link = netlink.link_by_name(&ifname).await?;
    println!("interface: {link:?}");

    let mut mac = [0u8; 6];
    if link.hwaddr.len() != 6 {
        return Err(format!("interface {ifname} has a non-Ethernet hardware address").into());
    }
    mac.copy_from_slice(&link.hwaddr);

    if !link.is_up {
        netlink.set_link_up(link.index).await?;
        println!("brought {ifname} up");
    }

    let socket = RawIcmp6Socket::open(link.index as i32)?;
    println!("opened raw ICMPv6 socket (have CAP_NET_RAW)");

    let mut client = Ipv6NdClient::new(
        ifname.clone(),
        link.index,
        socket,
        IidScheme::Eui64 { mac },
        netlink,
        events,
        false,
    )
    .await?;

    println!("sending Router Solicitation on {ifname}, waiting up to 15s for an RA...");
    match tokio::time::timeout(std::time::Duration::from_secs(15), client.run()).await {
        Ok(Err(e)) => println!("client exited with an error: {e}"),
        Ok(Ok(())) => unreachable!("run() only returns on error"),
        Err(_elapsed) => {
            let routers = client.router_list().routers();
            println!("timed out after 15s; routers seen: {}", routers.len());
            for r in routers {
                println!(
                    "  router {} managed={} other_config={} prefixes={}",
                    r.source,
                    r.managed,
                    r.other_config,
                    r.prefixes.len()
                );
                for p in &r.prefixes {
                    println!(
                        "    prefix {}/{} on_link={} autonomous={} address={:?}",
                        p.prefix, p.prefix_len, p.on_link, p.autonomous, p.address
                    );
                }
            }
        }
    }

    Ok(())
}
