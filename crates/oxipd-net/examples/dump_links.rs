//! Manual runtime sanity check for `oxipd_net::netlink`: dumps every link
//! and the loopback interface's addresses. Read-only, no root required.
//! Run with: `cargo run -p oxipd-net --example dump_links`

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, _events) = oxipd_net::netlink::NetlinkClient::spawn()?;

    let lo = client.link_by_name("lo").await?;
    println!("lo: {lo:?}");

    let addrs = client.addrs(lo.index).await?;
    println!("lo addrs: {addrs:?}");

    Ok(())
}
