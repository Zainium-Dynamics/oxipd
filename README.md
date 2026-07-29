# oxipd

A from-scratch Rust rewrite of [dhcpcd](https://github.com/NetworkConfiguration/dhcpcd),
targeting **Linux only**: a DHCPv4 + DHCPv6 + IPv6 Router Advertisement/SLAAC client daemon.

This is a clean-slate design (new config format, new `oxipdctl` CLI, new hook/event
contract) rather than a dhcpcd drop-in replacement. See `PLAN.md` for the full
architecture writeup and milestone breakdown this project is being built against.

## Status

**The DHCPv4 client works end-to-end against a real DHCP server** (verified in a
network namespace + veth pair against `dnsmasq`: DISCOVER → OFFER → REQUEST → ACK,
ARP-probed, and the address actually configured on the interface via oxipd's own
netlink code — see `crates/oxipd-core/examples/dhcp4_client.rs`). DHCPv6/IPv6-RA,
the control socket, and config/CLI are not implemented yet. 87+ tests across the
workspace, zero clippy warnings.

- `oxipd-proto` — pure wire codecs, no I/O: `dhcpv4` (DHCPv4/BOOTP, RFC 2132
  option-overload + RFC 3396 long-option handling), `arp` (RFC 5227 probe/
  announcement packets), `ndp` (RFC 4861 Router Solicitation/Advertisement +
  Prefix Information/MTU/RFC 4191 Route Information/RFC 8106 RDNSS options).
- `oxipd-net` — `checksum` (RFC 1071 Internet checksum + IPv4/UDP and IPv6/ICMPv6
  pseudo-header variants), `netlink` (async `rtnetlink` wrapper: link/address/route
  dump+mutate+event-stream, verified live against the kernel), `packet` (non-
  blocking `AF_PACKET`/`SOCK_RAW` sockets scoped by EtherType, no kernel BPF filter
  — see the module docs for why — verified to fail cleanly with `EPERM` without
  `CAP_NET_RAW`).
- `oxipd-privsep` — fork-based privilege separation: a `SOCK_SEQPACKET` +
  `SCM_RIGHTS` channel, a tagged request/response protocol, capability dropping,
  and both the synchronous privileged-helper loop and the async engine-side
  client. Verified end to end (fork → ping → open-a-socket-on-my-behalf → clean
  shutdown, `cargo run -p oxipd-privsep --example roundtrip`).
- `oxipd-core::arp`/`ipv4ll` — the RFC 5227 probe/announce/defend engine and RFC
  3927 IPv4 Link-Local address selection, both with the core policy (conflict
  detection, address picking) isolated as pure, unit-tested functions.
- `oxipd-core::dhcp4` — the whole DHCPv4 client: a pure state machine (`Dhcp4Fsm`,
  DISCOVER/OFFER/REQUEST/ACK/NAK/INIT-REBOOT/ARP-probing/RENEW/REBIND/expiry/
  RELEASE), pure timing (retransmit/NAK backoff, T1/T2) and lease-extraction
  modules, a pure message-codec bridge (`message`, `raw_frame` — including
  hand-computed IPv4/UDP checksums for the pre-address-bind window), and the
  async shell (`client`) that drives it all over real sockets + netlink. This is
  the one live-verified end-to-end, per the note above.
- `oxipd-core::ipv6::slaac`/`ipv6nd` — SLAAC interface-identifier generation
  (RFC 4291/2464 Modified EUI-64, RFC 7217 stable-private, RFC 5453 reserved-IID
  rejection) and the pure Router-Advertisement-processing policy (M/O flag →
  DHCPv6 mode, RFC 4862 §5.5.3.e's lifetime-floor rule). The stateful router/
  prefix-lifecycle tracking and the RS/RA raw-ICMPv6-socket shell aren't built yet.

Not yet done for the DHCPv4 client specifically: default-route installation,
lease-file persistence (for INIT-REBOOT across restarts), hook/event execution,
and running IPv4LL alongside DHCP. Full uid-dropping while retaining capabilities
(running the privsep helper as non-root) needs root to test and is deferred —
see `oxipd-privsep::privileges`'s module docs.

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
