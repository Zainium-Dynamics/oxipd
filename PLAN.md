# oxipd — a Rust rewrite of dhcpcd (Linux, DHCPv4+DHCPv6+IPv6-RA client)

## Context

`/home/alizain/Downloads/dhcpcd-10.3.2` is dhcpcd, a ~45,600-line C DHCP/DHCPv6/IPv4LL client
daemon with BSD/Solaris/Linux support and multi-process privilege separation. It's old C code
(manual malloc'd packet buffers, hand-rolled checksums, `#ifdef`-per-platform sprawl) and the
user wants a from-scratch Rust reimplementation, named **oxipd**, that keeps the good ideas
(privilege separation, the DHCP/DHCPv6/ARP/IPv4LL/RA state machines, the netlink-driven
interface model) but is designed cleanly instead of ported mechanically.

Decisions confirmed with the user:
- **Linux only** — drop BSD/Solaris backends, kqueue, Capsicum/pledge entirely.
- **Clean-slate design** — new config format, new CLI (`oxipd` + `oxipdctl`), new hook/event
  contract. Not a dhcpcd.conf/dhcpcd-run-hooks drop-in.
- **v1 scope = DHCPv4 + DHCPv6 + IPv6 Router Advertisement/SLAAC together** (the user chose the
  larger combined milestone over a DHCPv4-only first cut). This is a substantial amount of code
  (research below estimates 13,000–20,000 lines of Rust for parity); it will be built in the
  sequenced milestones below so the tree stays compilable and testable throughout, starting in
  this session and continuing across follow-up sessions — it is not realistic to land all of v1
  in a single pass.

Research already performed (three parallel deep reads of the C source) established:
1. **Core architecture**: single-threaded event loop (`eloop.c`, epoll-backed on Linux),
   multi-process privsep (`privsep*.c`) splitting a privileged root proxy / unprivileged network
   proxy / control-socket proxy, netlink-driven interface state (`if-linux.c`).
2. **DHCPv4/ARP/IPv4LL** (`dhcp.c`, `arp.c`, `ipv4ll.c`): `DHS_*` state machine, RFC2131-ish
   (not strictly literal) backoff (4s→8s→…→64s ±1s jitter), raw `AF_PACKET` I/O with hand
   checksums pre-bind, RFC5227 ARP probe/announce/defend, RFC3927 IPv4LL address picking.
3. **DHCPv6/IPv6-ND** (`dhcp6.c`, `ipv6.c`, `ipv6nd.c`): `DH6S_*` state machine, RFC8415
   backoff constants, M/O-flag-driven DHCPv6 startup from RA processing, SLAAC (EUI-64 /
   RFC7217 / RFC4941), prefix delegation subnetting (auto subnet-id from ifindex, RFC6603
   PD-exclude, parent/child prefix linkage).

Full findings are in this session's context; the plan below distills them into concrete Rust
architecture and a build order. RFC3118 DHCP auth is explicitly **out of scope** (both research
passes agreed it's obsolete and near-unused; treat unknown DHCP option 90 as opaque).

---

## Workspace layout

```
oxipd/
  Cargo.toml                     # workspace
  crates/
    oxipd-proto/                 # wire codecs only, no I/O: DHCPv4, DHCPv6, ARP, ND/RA options
    oxipd-net/                   # netlink client, raw AF_PACKET/ICMPv6 sockets, checksums
    oxipd-privsep/               # privileged-helper IPC framework
    oxipd-config/                # CLI (clap) + TOML config + option tables
    oxipd-core/                  # state machines: dhcp4, dhcp6, arp, ipv4ll, ipv6nd/slaac, routes
    oxipd-ctl/                   # control-socket protocol + server
  src/main.rs                    # oxipd daemon binary — wires crates together
  src/bin/oxipdctl.rs            # CLI client binary
```

Rationale: `oxipd-proto` and `oxipd-core`'s FSMs are the highest-value, highest-risk code
(parsing untrusted network input, RFC-compliance-sensitive timing) — keeping them free of
tokio/netlink/IPC dependencies means they can be unit-tested and fuzzed as pure functions
without a network namespace.

## Process / privilege model (simplified from dhcpcd's 3-process + dynamic-children design)

Two long-lived processes, replacing dhcpcd's `ps_root`/`ps_inet`/`ps_ctl` + per-listener
children:

- **`privileged` helper**: keeps `CAP_NET_ADMIN`+`CAP_NET_RAW` (via Linux capabilities, not
  full root where avoidable), and does only mechanical operations requested by the engine:
  create/bind raw `AF_PACKET` and `ICMPv6` sockets and hand the fd back via `SCM_RIGHTS`,
  issue rtnetlink mutations (add/del address, add/del route) on request, run the hook
  script/exec the event webhook, read/write the lease-file directory. It does **not** parse
  any network-received bytes.
- **`engine`** (unprivileged, runs as a dedicated `_oxipd` user, seccomp-filtered): owns every
  state machine (DHCPv4, DHCPv6, ARP, IPv4LL, IPv6-ND/SLAAC), parses all untrusted packets, and
  drives the tokio event loop. Talks to `privileged` over a `UnixDatagram` `SOCK_SEQPACKET`
  socketpair with a small tagged-enum request/response protocol (`oxipd-privsep`), not a
  generic "serialized syscall" like dhcpcd's `ps_msghdr` — enumerate the actual operations
  needed (`OpenPacketSocket{ifindex, ethertype}`, `OpenIcmp6Socket{ifindex}`, `RouteMutate{...}`,
  `AddrMutate{...}`, `RunHook{...}`, `ReadLease{...}`/`WriteLease{...}`) instead of proxying
  arbitrary `sendmsg`/`ioctl` calls.
- Rust's memory safety already removes most of the value of dhcpcd's per-listener-process
  isolation and the separate control-socket-proxy process, so those are deliberately dropped;
  the engine can own the control-socket listener directly.
- Seccomp filter for `engine`: build an explicit allow-list with the `seccompiler` crate
  (syscalls needed: epoll/timerfd, socket send/recv on the already-open UDP/privsep fds, no
  raw-socket or netlink-mutation syscalls at all since those only happen in `privileged`).

## Event loop / async runtime

- `tokio`, **single-threaded `current_thread` runtime** (mirrors dhcpcd's single-threaded
  design; avoids `Send`/`Sync` friction across the whole state-machine graph).
- `rtnetlink` + `netlink-packet-route` for link/address/route dump, mutate, and the
  multicast event stream (replaces the manual `if_getnetlink`/`add_attr_l` TLV building in
  `if-linux.c`).
- `tokio::time::sleep`/`interval` for every retransmit/T1/T2/lease timer — replaces `eloop`'s
  sorted-timer-list + queue-tag cancellation with per-state-machine `JoinHandle`s that are
  simply dropped/aborted on state transition.
- Raw `AF_PACKET`/`ICMPv6` sockets wrapped in `tokio::io::unix::AsyncFd` (no existing crate
  covers `SO_ATTACH_FILTER`+`ICMP6_FILTER` well, so `oxipd-net` owns this glue directly).

## DHCPv4 (`oxipd-core::dhcp4`, `oxipd-proto::dhcpv4`)

- Message codec: zero-copy option walker (`fn options(&self) -> impl Iterator<Item=(u8,&[u8])>`)
  that transparently merges RFC2132 option-overload (sname/file re-scan) and RFC3396
  same-code concatenation — the two correctness gotchas identified in research — then a typed
  encode path with RFC3396 chunking for outbound long options. Hand-rolled, not a
  parser-combinator crate, per research's finding that the imperative logic is unavoidable.
- FSM: Rust `enum Dhcp4State { Init, Discover, Request, Probe, Bound, Renew, Rebind, Reboot,
  Inform, Release }` (dropping unused `DHS_RENEW_REQUESTED`). Port constants verbatim for
  interop parity: backoff base 4s → doubling → cap 64s, ±1s jitter; T1=0.5·lease,
  T2=0.875·lease; min lease 20s; separate NAK backoff (1s doubling, cap 60s).
- Raw I/O: `AF_PACKET`/`SOCK_RAW` for the pre-bind window (DISCOVER/REQUEST-in-REBOOT/DECLINE),
  filtering done in userspace only (research found dhcpcd's own comment says it doesn't trust
  the kernel BPF filter anyway — skip installing one, remove the whole cBPF-bytecode-generation
  problem space). Manual Ethernet+IPv4+UDP framing with hand computed Internet checksum
  (~10 lines) for this window only; a plain `tokio::net::UdpSocket` once `Bound`.
- ARP (`oxipd-core::arp`): RFC5227 probe/announce/defend as a small reusable module consumed
  by both DHCPv4 (DAD on offered address) and IPv4LL, communicating via channels/trait objects
  instead of C function pointers. Constants ported verbatim: PROBE_WAIT 1s, PROBE_NUM 3,
  PROBE_MIN/MAX 1–2s, ANNOUNCE_WAIT 2s, ANNOUNCE_NUM 2, ANNOUNCE_INTERVAL 2s, MAX_CONFLICTS 10,
  RATE_LIMIT_INTERVAL 60s, DEFEND_INTERVAL 10s. Skip our own first gratuitous ARP announce
  (Linux kernel already sends one on address add, matching dhcpcd's own Linux special-case).
- IPv4LL (`oxipd-core::ipv4ll`): RFC3927 169.254.0.0/16 picking (exclude first/last /24), RNG
  seeded from the interface MAC (does not need bit-exact reproducibility with dhcpcd's
  `random()`/`initstate()` sequence — just the "usually same address across reboots" policy),
  conflict/rate-limit constants verbatim, coexists with real DHCP and is torn down once a lease
  binds.

## IPv6 RA / SLAAC / ND (`oxipd-core::ipv6nd`, `oxipd-core::ipv6`)

- Raw ICMPv6 socket, `ICMP6_FILTER` allow-listing only `ND_ROUTER_ADVERT` inbound; RS sent to
  `ff02::2` with source-link-layer-address option, retransmitted every 4s up to 3 times with
  `MAX_RTR_SOLICITATION_DELAY` initial jitter.
- RA parsing: Prefix Information (L/A bits), MTU, RDNSS/DNSSL, RFC4191 Route Information
  (including default-router preference bits); M/O flags drive DHCPv6 startup mode
  (`Managed` → stateful, `Other` → stateless-inform-only), only re-triggering on genuinely
  changed RA content (mirrors dhcpcd's raw-bytes diff to avoid re-firing every periodic RA).
- SLAAC IID generation, 3 schemes: EUI-64 (with RFC5453 reserved-IID rejection), RFC7217
  stable-private (SHA-256 over prefix‖hwaddr‖ifname‖dad-counter‖persisted secret, via the
  `sha2` crate), RFC4941 temporary/privacy addresses with desync factor and pre-expiry
  regeneration timer.
- Kernel handoff: disable kernel SLAAC entirely (`IFLA_INET6_ADDR_GEN_MODE = NONE` via
  rtnetlink, `net.ipv6.conf.<if>.{autoconf,accept_ra}=0` via sysctl) so oxipd owns RS/RA/DAD
  timing itself, then install addresses via `RTM_NEWADDR` with real `IFA_CACHEINFO`
  valid/preferred lifetimes (kernel-enforced expiry) and read DAD results back off
  `IFA_F_TENTATIVE`/`IFA_F_DADFAILED` in the netlink address-event stream (Linux reports this
  natively — no polling needed). Push hoplimit/reachable-time/retrans-timer sysctls from
  received RA values.
- Router list: track per-(interface,source) `Router` structs, expire on lifetime/carrier-loss,
  NUD-driven reachability re-solicitation if the last usable default router disappears.

## DHCPv6 (`oxipd-core::dhcp6`, `oxipd-proto::dhcpv6`)

- FSM: Rust enum over the 14 live states (`Init, Discover, Request, Bound, Renew, Rebind,
  Confirm, Inform, Informed, Decline, Delegated, Release, Released, ManualRebind` — dropping
  the two dead C states). Message types: SOLICIT/ADVERTISE/REQUEST/CONFIRM/RENEW/REBIND/REPLY/
  RELEASE/DECLINE/INFORMATION-REQUEST/RECONFIGURE.
- Replace the C code's "keep raw wire bytes and re-scan for each option lookup" pattern with a
  parsed `Vec<Dhcp6Option>`/multimap once per received message (DHCPv6 options may legally
  repeat).
- Retransmission timers per RFC8415 §15, ported verbatim per message type (SOL/REQ/CNF/REN/
  REB/INF/REL/DEC/REC `*_MAX_DELAY`/`TIMEOUT`/`MAX_RT`/`MAX_RC` constants), including the
  asymmetric initial-vs-retransmit jitter ranges and server-adjustable `SOL_MAX_RT`/
  `INF_MAX_RT` (RFC8415 clamped [60,86400]).
- DUID: LLT/LL/UUID generation, persisted once and shared as the DHCPv6 client-id.
- IA_NA/IA_TA/IA_PD parsing keyed by IAID; **prefix delegation subnetting** ported carefully
  (this is the highest logic-risk item per research, not the largest in LOC): auto-derive a
  subnet id from the downstream interface's kernel ifindex when the user hasn't configured one,
  `new_prefix_len = delegated_len + bits_needed`, rounded to 64 or up to a multiple of 4;
  RFC6603 PD-exclude special-casing; parent/child prefix linkage so delegated sub-prefixes are
  deprecated/torn down together with their parent lease; suppress the "reject route" for the
  whole delegated block when it was handed to exactly one downstream interface unmodified.

## Route table (`oxipd-core::routes`)

Single `BTreeMap`/`BTreeSet`-based store with a custom `Ord` mirroring kernel table order
(dest+mask+metric) for the "what does the kernel have" view, and a separate ranked view for
"which interface's route wins when several could supply the same destination" — replacing the
C code's rb_tree-node-in-three-trees-at-once trick, which has no clean Rust equivalent and
isn't worth replicating.

## Config, CLI, hooks, control socket (all clean-slate, per user's decision)

- **Config**: `clap`-derived CLI flags + a TOML config file with global defaults and
  `[interface.<name>]` / glob-matched sections, replacing dhcpcd.conf's `interface`/`ssid`/
  `profile` block syntax. Well-known DHCPv4/DHCPv6/ND option numbers ported as static Rust
  `const` tables (from the RFCs / `dhcpcd-definitions.conf`'s numeric IDs), not a runtime text
  parser.
- **Hooks/events**: a hook script (if configured) is invoked with a single structured JSON blob
  on stdin describing the transition (interface, reason, old/new lease) instead of ~100 env
  vars — simpler and still shell-scriptable via `jq`. In parallel, `oxipd-ctl` exposes the same
  events as a live subscription (`tokio::sync::broadcast`) for `oxipdctl monitor`, replacing
  dhcpcd's `--listen` control-socket push mechanism.
- **Control socket**: a single `UnixStream` listener owned directly by the engine (no separate
  proxy process), speaking a small length-prefixed JSON (or `bincode`) protocol with commands
  `status`, `renew`, `release`, `rebind`, `reconfigure`, `dump-lease`, `monitor`, `version`.
  `oxipdctl` is the CLI client.

## Testing strategy

- `oxipd-proto`: unit + `cargo fuzz` targets against captured real-world DHCPv4/DHCPv6/RA
  packet fixtures — pure functions, no network needed, highest-value target since this parses
  untrusted input.
- `oxipd-core` FSMs: driven in tests via `tokio::time::pause()` (virtual clock) and a
  channel-backed fake transport, to run full DISCOVER→BOUND→RENEW→REBIND→EXPIRE (and the
  DHCPv6/RA equivalents) sequences deterministically without real interfaces.
- Integration: a Linux network-namespace test (`ip netns` + veth pair) with `dnsmasq` or `kea`
  as the real DHCP/DHCPv6/RA-emitting peer, verifying oxipd actually acquires a lease and
  configures the veth — this is the concrete "drive it end-to-end" verification step once M3
  is reachable.

## Build order

Sequenced so the tree stays compiling and independently testable at every step; all within the
combined v1 scope the user asked for.

- **M0** — Workspace scaffold, `oxipd-proto` crate skeleton (DHCPv4 message struct + option
  iterator, unit tests against a couple of hand-built byte fixtures), clippy/test CI.
- **M1** — `oxipd-net`: rtnetlink wrapper (link/addr/route dump + mutate + event stream), raw
  `AF_PACKET` socket helper, checksum utilities.
- **M2** — `oxipd-privsep`: privileged-helper process, the tagged IPC protocol, capability
  dropping + seccomp skeleton; prove a minimal round trip (engine asks privileged helper to open
  a raw socket, gets the fd back).
- **M3** — DHCPv4 client end to end: FSM + ARP + IPv4LL wired to `oxipd-net`/`oxipd-privsep` —
  first real lease acquired and configured in a `veth`/netns test against `dnsmasq`.
- **M4** — IPv6 RA/ND + SLAAC: kernel-autoconf handoff, address install with real lifetimes,
  RFC7217/RFC4941 IID schemes, router list management.
- **M5** — DHCPv6 client: FSM, IA_NA/IA_TA, prefix delegation subnetting.
- **M6** — Control socket + `oxipdctl` + hook/event mechanism.
- **M7** — Config file/CLI polish, lease persistence format, systemd unit.
- **M8** — Test hardening: fuzz targets wired into CI, netns integration tests, docs/README.

This session starts M0 (and as much of M1 as time allows) immediately after this plan is
approved, and continues through the remaining milestones in follow-up work — a faithful v1 is
realistically 13,000–20,000 lines of Rust (DHCPv6+IPv6ND alone is estimated at 6,000–9,000
lines for RFC-compliance parity; DHCPv4+ARP+IPv4LL roughly 4,000–6,000; netlink/privsep/config/
control-socket infrastructure roughly 3,000–5,000), so it will not land in one pass.

## Verification

- `cargo test` + `cargo clippy -- -D warnings` at every milestone.
- From M3 onward: manual end-to-end check in a `sudo ip netns add oxipd-test` + veth pair +
  `dnsmasq --dhcp-range=...` sandbox — actually run `oxipd` against it and confirm a real
  address/route gets configured on the veth, per this project's own guidance to exercise
  runtime behavior rather than relying on tests alone for anything touching netlink/raw sockets.
