//! Manual runtime sanity check for the M2 milestone: fork the privileged
//! helper, ping it, and ask it to open a raw packet socket on our behalf,
//! all before any tokio runtime exists in the parent (per
//! `oxipd_privsep::spawn::spawn`'s safety contract).
//!
//! Run with: `cargo run -p oxipd-privsep --example roundtrip`

use oxipd_privsep::{client::PrivsepClient, spawn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Must happen before any tokio runtime is built (see spawn::spawn docs).
    let helper = spawn::spawn()?;
    println!("forked privileged helper, pid={}", helper.pid);

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let client = PrivsepClient::new(helper.channel_fd)?;

        client.ping().await?;
        println!("ping: ok");

        match client.open_packet_socket(1 /* lo */, oxipd_net::packet::ETH_P_ARP).await {
            Ok(fd) => {
                let sock = oxipd_net::packet::RawSocket::from_owned_fd(fd, 1)?;
                println!(
                    "open_packet_socket: ok (have CAP_NET_RAW), ifindex={}",
                    sock.ifindex()
                );
            }
            Err(e) => println!("open_packet_socket: failed as expected without privilege: {e}"),
        }

        client.shutdown().await?;
        println!("shutdown: ok");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let mut status: libc::c_int = 0;
    // SAFETY: `helper.pid` is our own just-forked, not-yet-reaped child.
    unsafe {
        libc::waitpid(helper.pid, &mut status, 0);
    }
    println!("helper exited with status {status}");

    Ok(())
}
