//! `/proc/sys/net/ipv6` knobs oxipd needs to hand SLAAC/RA/DAD control
//! over from the kernel to `oxipd-core::ipv6nd` (matching dhcpcd's own
//! `if_setup_inet6`/`if_applyra` on Linux) — plain file writes, no
//! netlink involved for these.

use std::io;

// A plain (synchronous) write: these are single small writes to /proc
// files that never block in practice, so pulling in tokio's "fs" feature
// (which spawns a blocking-pool thread per call) isn't worth it here.
async fn write_conf(family_dir: &str, ifname: &str, key: &str, value: &str) -> io::Result<()> {
    let path = format!("/proc/sys/net/ipv6/{family_dir}/{ifname}/{key}");
    std::fs::write(path, value)
}

/// Stop the kernel from running its own Router Solicitation/Advertisement
/// handling and stateless address autoconfiguration on `ifname` — oxipd
/// does RS/RA processing and SLAAC itself in userspace (see
/// `oxipd_core::ipv6nd`), so the kernel doing the same would race it.
pub async fn disable_kernel_autoconf(ifname: &str) -> io::Result<()> {
    write_conf("conf", ifname, "autoconf", "0").await?;
    write_conf("conf", ifname, "accept_ra", "0").await?;
    Ok(())
}

/// Push a Router Advertisement's Cur Hop Limit onto the interface, so
/// kernel-originated traffic (which oxipd doesn't intercept) uses the
/// router-advertised value too.
pub async fn set_hop_limit(ifname: &str, hop_limit: u8) -> io::Result<()> {
    write_conf("conf", ifname, "hop_limit", &hop_limit.to_string()).await
}

/// Push a Router Advertisement's reachable-time/retrans-timer onto the
/// interface's Neighbor Unreachability Detection parameters.
pub async fn set_neighbor_timers(ifname: &str, reachable_time_ms: u32, retrans_timer_ms: u32) -> io::Result<()> {
    write_conf("neigh", ifname, "base_reachable_time_ms", &reachable_time_ms.to_string()).await?;
    write_conf("neigh", ifname, "retrans_time_ms", &retrans_timer_ms.to_string()).await?;
    Ok(())
}
