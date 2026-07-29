//! Manual runtime sanity check for `oxipd_net::icmp6::open_raw_fd`:
//! confirms it fails cleanly (no panic) without `CAP_NET_RAW`.
//! Run with: `cargo run -p oxipd-net --example try_icmp6_socket`

fn main() {
    match oxipd_net::icmp6::open_raw_fd(1 /* lo */) {
        Ok(_) => println!("opened raw ICMPv6 socket (have CAP_NET_RAW / root)"),
        Err(e) => println!("failed as expected without privilege: {e}"),
    }
}
