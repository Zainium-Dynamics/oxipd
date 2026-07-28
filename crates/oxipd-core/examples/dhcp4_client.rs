//! Manual runtime check for the M3 async shell (`Dhcp4Client`): opens raw
//! `AF_PACKET` sockets directly (no privsep wiring yet — that's a separate
//! milestone) on a real interface and runs the DHCPv4 acquisition flow for
//! up to 15 seconds.
//!
//! Requires `CAP_NET_RAW`/root, and a real DHCP server reachable on the
//! given interface to get past DISCOVER. Run with:
//! `cargo run -p oxipd-core --example dhcp4_client -- <ifname>`

use oxipd_core::dhcp4::{Dhcp4Client, Event};
use oxipd_net::netlink::NetlinkClient;
use oxipd_net::packet::{RawSocket, ETH_P_ARP, ETH_P_IP};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let ifname = std::env::args().nth(1).ok_or("usage: dhcp4_client <ifname>")?;

    let (netlink, _events) = NetlinkClient::spawn()?;
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

    let dhcp_socket = RawSocket::open(link.index as i32, ETH_P_IP)?;
    let arp_socket = RawSocket::open(link.index as i32, ETH_P_ARP)?;
    println!("opened raw sockets (have CAP_NET_RAW)");

    let mut client = Dhcp4Client::new(mac, link.index, dhcp_socket, arp_socket, netlink);

    println!("starting DHCPv4 DISCOVER on {ifname}, waiting up to 15s for a lease...");
    match tokio::time::timeout(std::time::Duration::from_secs(15), client.run(Event::Start)).await {
        Ok(Err(e)) => println!("client exited with an error: {e}"),
        Ok(Ok(())) => unreachable!("run() only returns on error"),
        Err(_elapsed) => println!("timed out after 15s; final state: {:?}", client.fsm().state()),
    }

    Ok(())
}
