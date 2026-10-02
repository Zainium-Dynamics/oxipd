# oxipd

A DHCPv4, DHCPv6 and IPv6 RA/SLAAC client daemon for Linux, written in Rust.
Think of it as a from-scratch rewrite of [dhcpcd](https://github.com/NetworkConfiguration/dhcpcd).

## Status

| Part | State |
|------|-------|
| DHCPv4 + ARP + IPv4LL | works, tested against dnsmasq |
| IPv6 RA / SLAAC | done, not yet tested on a live router |
| DHCPv6 | not started |
| Control socket, config, hooks | not started |

## Build and test

```
cargo build
cargo test
cargo clippy --all-targets
```

Try the DHCPv4 client (needs root or `CAP_NET_RAW` + `CAP_NET_ADMIN`):

```
cargo run -p oxipd-core --example dhcp4_client -- <ifname>
cargo run -p oxipd-core --example ipv6nd_client -- <ifname>
```

## More

- [ARCHITECTURE.md](ARCHITECTURE.md) - how the code is laid out
- [PLAN.md](PLAN.md) - milestones and design decisions

Linux only. License: BSD-2-Clause.
