# oxipd

A from-scratch Rust rewrite of [dhcpcd](https://github.com/NetworkConfiguration/dhcpcd),
targeting **Linux only**: a DHCPv4 + DHCPv6 + IPv6 Router Advertisement/SLAAC client daemon.

This is a clean-slate design (new config format, new `oxipdctl` CLI, new hook/event
contract) rather than a dhcpcd drop-in replacement. See `PLAN.md` for the full
architecture writeup and milestone breakdown this project is being built against.

## Status

Early scaffold. Implemented so far:

- `oxipd-proto::dhcpv4` — a zero-copy DHCPv4/BOOTP message parser and a typed builder,
  handling RFC 2132 option-overload and RFC 3396 long-option concatenation.
- `oxipd-net::checksum` — RFC 1071 Internet checksum + the IPv4/UDP pseudo-header
  variants needed for the pre-address-bind raw-socket DHCP path.

Everything else (netlink integration, privilege separation, the DHCPv4/DHCPv6/ARP/
IPv4LL/IPv6-ND state machines, the control socket, config/CLI) is not implemented yet.

## Layout

```
crates/
  oxipd-proto/    wire codecs only, no I/O (DHCPv4, DHCPv6, ARP, ND/RA options)
  oxipd-net/      netlink client, raw AF_PACKET/ICMPv6 sockets, checksums
  oxipd-privsep/  privileged-helper process + IPC framework
  oxipd-config/   CLI + TOML config + option tables
  oxipd-core/     state machines: dhcp4, dhcp6, arp, ipv4ll, ipv6nd/slaac, routes
  oxipd-ctl/      control-socket protocol + server
src/main.rs       oxipd daemon binary
src/bin/oxipdctl.rs
```

## Building

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Requires a Linux target; there is no BSD/Solaris backend by design.
