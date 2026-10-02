# Architecture

## Crates

```
oxipd-proto    wire codecs (DHCPv4, ARP, NDP). Pure functions, no I/O.
oxipd-net      netlink, raw AF_PACKET / ICMPv6 sockets, sysctl, checksums.
oxipd-privsep  privileged helper process and the IPC to talk to it.
oxipd-core     state machines: dhcp4, arp, ipv4ll, ipv6nd, slaac.
oxipd-config   CLI and config file (stub).
oxipd-ctl      control socket protocol (stub).
src/           the `oxipd` daemon and `oxipdctl` binaries.
```

Dependencies only point down: `core` uses `proto` and `net`; `proto` uses nothing.
Keeping `proto` and the state machines free of sockets means they can be
unit-tested without a network.

## Processes

Two processes, split by privilege:

- **privileged helper** keeps `CAP_NET_RAW` and `CAP_NET_ADMIN`. It opens raw
  sockets and passes the fds over with `SCM_RIGHTS`. It never parses packets.
- **engine** runs unprivileged. It owns all state machines and parses every
  packet from the network.

They talk over a `SOCK_SEQPACKET` socketpair using a small enum protocol
(`oxipd-privsep::proto`), not generic syscall forwarding.

## Event loop

Single-threaded tokio (`current_thread`). Timers are `tokio::time`; netlink
comes from `rtnetlink`; raw sockets are wrapped in `AsyncFd`.

## Pure core, async shell

Each protocol follows the same split:

- a pure part that takes inputs (packets, time) and returns decisions
- a thin async shell that does the socket and netlink calls

| Protocol | Pure part | Async shell |
|----------|-----------|-------------|
| DHCPv4 | `dhcp4::fsm`, `timing`, `lease` | `dhcp4::client` |
| IPv6 RA | `ipv6nd::router_list` (returns `RaEvent`s) | `ipv6nd::client` |

## DHCPv4

`Dhcp4Fsm` handles Discover, Request, ARP probe, Bound, Renew, Rebind and
expiry. Before the interface has an address it sends through a raw
`AF_PACKET` socket with hand-built IP/UDP headers (`raw_frame`). After that
it is plain UDP. `arp` and `ipv4ll` follow RFC 5227 and RFC 3927.

## IPv6 RA and SLAAC

`Ipv6NdClient` takes over from the kernel (`accept_ra=0`, `autoconf=0`,
addr-gen-mode none), sends Router Solicitations, and feeds each RA into
`RouterList`. `RouterList` tracks routers and prefixes and emits:

- `ConfigureAddress` / `RemoveAddress` (kernel enforces the lifetimes)
- `AddDefaultRoute` / `RemoveDefaultRoute`
- `ApplyLinkParameters` (hop limit, reachable time, retrans timer)
- `Dhcp6` (M/O flag trigger, not acted on until DHCPv6 exists)

Address identifiers come from `ipv6::slaac`: EUI-64, RFC 7217 stable-private,
and RFC 8981 temporary. If the kernel reports a duplicate address (DAD
failure), RFC 7217 retries with a new counter; EUI-64 just drops the address.

## Not built yet

DHCPv6 and prefix delegation, a route table module, config and CLI, control
socket, hooks, lease persistence, systemd unit, seccomp.
