//! Manual runtime sanity check for `oxipd_net::packet::RawSocket`: confirms
//! opening a raw socket fails cleanly (no panic) without CAP_NET_RAW, and
//! succeeds when run with it (e.g. via `sudo` or `setcap cap_net_raw+ep`).
//! Run with: `cargo run -p oxipd-net --example try_raw_socket`

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match oxipd_net::packet::RawSocket::open(1 /* lo */, oxipd_net::packet::ETH_P_ARP) {
        Ok(_) => println!("opened raw socket (have CAP_NET_RAW / root)"),
        Err(e) => println!("failed as expected without privilege: {e}"),
    }
}
