# lando

A from-scratch Tailscale client for the Raspberry Pi Pico 2 W, written in Rust.

The goal is a device you plug in, configure once over USB, and then reach from
anywhere on your tailnet — with no port forwarding, no dynamic DNS, no router
changes, and no server of your own to run. Once it is on the tailnet it proxies
TCP onto the LAN it sits on, so a UPnP amplifier or any other local device
becomes reachable remotely.

Nothing here uses the official Tailscale client or daemon. It speaks the wire
protocol directly.

## Status

Early. The control-plane path works against the real hosted control plane.

| Stage | |
|---|---|
| HTTP/1.1 upgrade, cleartext `:80` | working |
| Noise IK handshake | working |
| ts2021 early payload | working |
| HTTP/2 over Noise | working |
| `POST /machine/register` | working — registers and authorizes |
| Identity persistence across restarts | working |
| `POST /machine/map` (netmap long-poll) | working — node reports online |
| WireGuard handshake (both roles) | working — interops with boringtun |
| WireGuard transport + replay window | working — interops with boringtun |
| WireGuard timers / rekey / cookies | not started |
| DERP framing + NaCl handshake | working — handshakes with a live relay |
| DERP packet relay datapath | working — real Tailscale client handshakes over a live relay |
| TSMP ping/pong | working — `tailscale ping` succeeds |
| TCP over the tunnel (smoltcp) | working |
| SOCKS5 proxy to the LAN | working — reaches a real LAN device |
| Transparent port-forward | working — no client configuration at all |
| RP2350 firmware — USB console | working — logs, and reboots to bootloader on `b` |
| RP2350 firmware — WiFi join | working — associates in ~3 s |
| RP2350 firmware — network stack | working — DHCP lease on the LAN |
| RP2350 firmware — datapath port | not started |
| USB provisioning to flash | working — image carries no secrets |

A node registered by `lando-host` shows up in the admin console as a real
machine, gets a tailnet address and a MagicDNS name, reports *online*, and
answers `tailscale ping`:

```
$ tailscale ping 100.64.0.1
pong from lando (100.64.0.1) via TSMP in 723ms
```

That round trip is a real Tailscale client reaching this implementation through
a live DERP relay: WireGuard handshake, session, TSMP decrypted and answered.
It also carries TCP: a SOCKS5 proxy listens on the tunnel address, so any
tailnet client can reach any host on the LAN the node sits on.

```
tailnet client ──WireGuard/DERP──▶ lando:1080  (SOCKS5)      ──▶ any LAN host
                                   lando:37193 (forwarded)   ──▶ one LAN host
```

A forwarded port needs nothing configured on the client — the tunnel address
behaves exactly as the LAN device does:

```sh
LANDO_FORWARD="37193=192.168.1.50:37193" cargo run -p lando-host -- node
curl http://lando-tailnet-ip:37193/...        # straight through
```

Verified end to end against a real UPnP amplifier: `HTTP/1.1 200 OK`, device
description and all.

**Reachability currently requires Headscale.** Registered against Tailscale's
hosted control plane the node comes online but peers are never told where to
reach it — see the protocol notes below.

## Layout

```
crates/tailscale-core/   no_std, sans-IO. Protocol state machines, zero I/O.
crates/lando-host/       std binary: runs the core on a dev machine.
crates/lando-fw/         no_std firmware for the Pico 2 W. (not yet present)
```

`tailscale-core` never touches a socket, a clock, or an allocator. Every
protocol is a state machine over byte slices, so the *same compiled logic* runs
under a debugger on a laptop and on a microcontroller that has neither a
debugger nor an operating system. Protocol code that can only be exercised by
flashing a board does not get exercised, and bare-metal debugging is a bad place
to discover that a length prefix is little-endian.

## Try it

```sh
cargo test
cargo run -p lando-host
```

With no pre-auth key present, `lando-host` registers interactively: it prints a
URL, you open it in a browser signed in to your tailnet, and a follow-up request
completes the login. For headless use — which is the point of the project —
supply a pre-auth key instead:

```sh
echo 'tskey-auth-...' > .lando-authkey
cargo run -p lando-host
```

`LANDO_TRACE=1` dumps the HTTP/2 frame exchange. Everything on the wire is
inside Noise, so a packet capture shows only ciphertext; this is the only way to
watch the protocol.

State lands in `.lando-state` (machine key and node key, mode `0600`). Both that
and `.lando-authkey` are gitignored. Treat a pre-auth key like an SSH private
key until it is used or revoked.

## Notes on the protocol

Some of this is undocumented, so a few findings worth recording:

- **The control channel needs no TLS.** `POST /ts2021` on **port 80**, in the
  clear, with the Noise initiation base64'd into `X-Tailscale-Handshake`. Noise
  supplies confidentiality and authentication on top. Port 443 exists as a
  TLS-wrapped fallback whose certificate upstream deliberately does not verify.
- **An early payload precedes HTTP/2.** After the handshake the server sends
  `\xff\xff\xffTS`, a 4-byte big-endian length, then JSON — currently a
  `nodeKeyChallenge`. Feed that to an HTTP/2 parser and it desynchronises and
  hangs forever waiting for a frame that never arrives.
- **The record nonce is big-endian.** Noise specifies little-endian; this does
  not follow it. Transport records also use empty AEAD associated data, while
  the handshake uses the running hash.
- **HPACK decoding is unnecessary.** Response HEADERS frames can be skipped
  entirely. Sending `SETTINGS_HEADER_TABLE_SIZE = 0` forbids the server from
  indexing, which makes that safe rather than merely convenient.
- **`WINDOW_UPDATE` is not optional.** The server's send window closes after
  65535 bytes and the connection then stalls silently.
- Noise frames cap at 4096 bytes, so the record layer needs one fixed buffer
  regardless of message size. Everything above it has to stream.
- **WireGuard disagrees with ts2021 on byte order.** Same cipher, same 12-byte
  nonce layout, but WireGuard counts little-endian and ts2021 big-endian. The
  netmap's frame length prefix is little-endian too, while every other length
  on the control connection is big-endian.
- **WireGuard's `mac1` uses BLAKE2s in keyed mode, not HMAC** — while its KDF
  uses HMAC. Swapping them yields handshakes a peer drops without reply, which
  is indistinguishable from a firewall problem.
- **An unparseable `IPNVersion` silently discards the entire Hostinfo.** No
  error is returned; the struct simply never appears. Everything inside it goes
  with it, including the `NetInfo` that tells peers where to reach you.
- **`derp1.tailscale.com` is not in DERP region 1's mesh.** Region 1's nodes are
  `derp1i`/`derp1h`. Connect to the wrong one and the relay accepts you,
  completes its handshake, and then quietly fails to route anything, because
  peers reach region 1 through servers yours is not meshed with.
- **Peers are only told where to reach you via `Hostinfo.NetInfo.PreferredDERP`.**
  Headscale turns that into `Node.HomeDERP`; Tailscale's hosted control plane
  ignores the identical request, so a node registered there stays unreachable.
  `Node.DERP` (`127.3.3.40:N`) is the deprecated form of the same thing.

## Testing

Unit tests that round-trip a protocol against its own implementation prove
self-consistency and nothing more — every KDF, DH ordering and hash-mixing
detail could be uniformly wrong and they would still pass. So the important
tests are the ones with a second opinion:

- The BLAKE2s HMAC and KDF are checked against vectors generated by Python's
  `hmac`/`hashlib`.
- The WireGuard handshake and transport are checked against
  [boringtun](https://github.com/cloudflare/boringtun), Cloudflare's independent
  implementation, in **both** directions — our initiator against its responder
  and vice versa, including transport packets each way. boringtun is a
  dev-dependency and never reaches the firmware build.

```sh
cargo test                                       # everything
cargo run -p lando-host -- derp                  # handshake against a real relay
cargo test -p tailscale-core --test interop_boringtun
cargo build --target thumbv8m.main-none-eabihf -p tailscale-core   # no_std check
```

## Caveats

The control protocol is not documented or stabilized by Tailscale, which treats
it as an internal interface. It changes. This is a hobby project and a
maintenance commitment, not a supported client — if you want a self-hosted
control plane you can pin, look at [Headscale](https://github.com/juanfont/headscale).

Prior art worth reading, both of which target ESP32:
[microlink](https://github.com/CamM2325/microlink) (C) and
[tailscale-esp32](https://github.com/0xdilo/tailscale-esp32) (Rust).

## License

MIT
