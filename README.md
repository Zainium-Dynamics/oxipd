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
- `oxipd-net::netlink` — an async `rtnetlink` wrapper: link lookup/up-down, address
  add/del/dump, route add/del/dump, and a merged link/address/route/neighbour
  multicast event stream. Verified against the live kernel (`cargo run -p oxipd-net
  --example dump_links` correctly dumps `lo`'s link info and addresses).
- `oxipd-net::packet` — a non-blocking `AF_PACKET`/`SOCK_RAW` socket bound to one
  interface + one EtherType (no kernel BPF filter — see the module docs for why),
  plus Ethernet framing helpers. Verified to fail cleanly with `EPERM` when run
  without `CAP_NET_RAW` (`cargo run -p oxipd-net --example try_raw_socket`).
- `oxipd-privsep` — the privilege-separation IPC framework: a `SOCK_SEQPACKET` +
  `SCM_RIGHTS` channel (`channel`), a tagged request/response protocol over it
  (`proto`), a fork-based helper spawner (`spawn`), Linux-capability dropping
  (`privileges`), and both the synchronous helper-side dispatch loop (`helper`)
  and the async engine-side client (`client`). Verified end to end: forking the
  helper, pinging it, and asking it to open a raw socket on the engine's behalf
  all work over the real IPC channel (`cargo run -p oxipd-privsep --example
  roundtrip`) — the `open_packet_socket` call correctly fails with `EPERM`
  without `CAP_NET_RAW`, exactly like the `oxipd-net` example above, proving the
  error propagates cleanly across the privilege boundary.
- `oxipd-proto::arp` — Ethernet/IPv4 ARP packet codec (parse/build) plus RFC 5227
  probe/announcement constructors.
- `oxipd-core::arp` — the RFC 5227 probe/announce/defend engine (`ArpProbe`), with
  the conflict-detection policy (`detects_conflict`) isolated as a pure, unit-tested
  function independent of any socket.
- `oxipd-core::ipv4ll` — RFC 3927 IPv4 Link-Local address selection: MAC-seeded,
  deterministic picking within the valid `169.254.0.0/16` sub-range, plus the
  probe-and-retry-with-backoff policy loop built on `ArpProbe`.
- `oxipd-core::dhcp4` — the DHCPv4 client as a pure state machine (`Dhcp4Fsm`):
  `handle(event) -> Vec<Action>`, covering DISCOVER/OFFER/REQUEST/ACK/NAK,
  INIT-REBOOT, ARP-probing every (re)assignment, RENEW/REBIND/lease-expiry, and
  RELEASE. Retransmit/NAK backoff and T1/T2 timing (`timing`) and DHCPACK lease
  extraction (`lease`) are their own tested units. Kept free of any I/O by design
  (see the module docs) so all 29 `oxipd-core` tests run instantly with no
  network namespace.

Not yet implemented: the async "shell" that drives `Dhcp4Fsm` over real raw/UDP
sockets and netlink (wiring `oxipd-net`/`oxipd-privsep` to the actions above),
DHCPv6/IPv6-ND/SLAAC, the control socket, and config/CLI. Full uid-dropping while
retaining capabilities (running the privsep helper as non-root) needs root to
test and is deferred — see `oxipd-privsep::privileges`'s module docs.

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
