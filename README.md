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
| WireGuard handshake (both roles) | implemented, not yet interop-tested |
| WireGuard transport + replay window | implemented, not yet interop-tested |
| WireGuard timers / rekey / cookies | not started |
| DERP relay client | not started |
| TCP port-forward / SOCKS5 | not started |
| RP2350 firmware | not started |

A node registered by `lando-host` shows up in the admin console as a real
machine, gets a tailnet address and a MagicDNS name, and reports *online* for
as long as the map long-poll is held open. It is not yet reachable — that needs
the WireGuard data plane.

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

"Implemented, not yet interop-tested" above means exactly that: the WireGuard
handshake round-trips against its own responder and both halves derive matching
keys, which proves self-consistency, not that a real peer will talk to it.

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
