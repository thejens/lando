# lando

A from-scratch Tailscale client for the Raspberry Pi Pico 2 W, in Rust. No
Tailscale daemon, no Go runtime, no Linux — the wire protocol on bare metal, in
392 KB of the RP2350's 512 KB of SRAM.

Plug the board into any network, configure it once over USB, and every device on
that LAN becomes reachable from your tailnet.

```
phone on 5G ──WireGuard──▶ DERP relay ──▶ Pico ──▶ 192.168.1.50:37193
                                                   any host on its LAN
```

## Why this is useful

Reaching a device on a home LAN from outside normally costs you one of these: a
port forward, a dynamic-DNS record, a VPN server to run and patch, or a cloud
relay you rent. Each is a permanent thing to maintain, and the first two put your
network on the public internet.

lando is a $7 board that removes all of them. It joins your tailnet as an
ordinary node and advertises its LAN as a subnet route, so from anywhere you
just address LAN hosts directly:

```sh
curl http://192.168.1.50:37193/description.xml    # from a phone on cellular
```

Every connection is end-to-end WireGuard, authenticated by your tailnet's
identity, and every connection is outbound — nothing about your network is
exposed, and the router is never touched.

It grew out of an earlier project that did the same job by parking an outbound
WebSocket at a Cloudflare Worker. That Worker was a permanent hosted dependency,
a second codebase to keep in sync, and a place where a device credential lived.
A tailnet already solves NAT traversal, identity, key exchange and transport
encryption, so none of it needs to exist.

It is also, as far as I can tell, the smallest complete Tailscale node there is:
control plane, WireGuard, disco, DERP and a TCP proxy in a microcontroller with
no MMU, no allocator and no operating system.

## What works

Running on hardware against Tailscale's real hosted control plane:

| | |
|---|---|
| Registers as a real node | tailnet IP, MagicDNS name, reports online |
| Reachable behind NAT | holds a DERP relay connection open, reconnects with backoff |
| Direct paths | disco endpoint validation, `tailscale ping` in ~39 ms on-LAN |
| Subnet router | advertises and routes its whole LAN over the tailnet |
| Provisioning | WiFi and tailnet credentials over USB; the image carries no secrets |

Measured, fetching a 172 KB file through the tunnel, byte-identical each time:

```
direct path    2.8 s   (61 KB/s)
via DERP       8.4 s   (20 KB/s)
```

The relay figure is dominated by per-packet cost — WireGuard and TLS are both in
software on a 150 MHz core. It is comfortable for controlling things and poor for
moving bulk data, which is the intended trade.

### Using it with a device's own app

Vendor apps generally work, because the tunnel forwards bytes and never parses
them — a WebSocket upgrade, a raw control protocol on an odd port, or UPnP SOAP
all cross unchanged. Two things decide whether a given app is happy:

- **It must let you enter an address.** Discovery does not cross the tunnel:
  mDNS and SSDP are both UDP multicast, and a tailnet is not a multicast
  domain. An app that can only find devices by scanning will not find them.
  Nor will a hostname like `device.local` resolve.
- **Its port must be in `PORTS`.** Ports are preallocated, so anything not
  listed is simply not routed. Read what the device advertises over mDNS rather
  than guessing — `dns-sd -Z _spotify-connect._tcp local` names both the port
  and the path. The amplifier this was built for turned out to use six:

  | | |
  |---|---|
  | `80` | web UI, and a WebSocket its vendor app upgrades to |
  | `84` | the vendor app's raw control protocol |
  | `8080` | Spotify Connect zeroconf, `/api/stream/spotify:zeroconf` |
  | `8008` / `8009` | Google Cast, HTTP and protobuf-over-TLS |
  | `37193` | UPnP/DLNA |

**What routing a port does not buy you.** Two cases are worth understanding
before assuming a protocol will work:

- **Spotify Connect needs the LAN only to pair.** Once a speaker has been handed
  credentials it holds its own connection to Spotify and is controlled through
  Spotify's servers — so it is already reachable from anywhere, with or without
  this device. What the tunnel adds is pairing a speaker remotely.
- **Google Cast is the opposite.** Its control channel is reachable, but clients
  find devices exclusively over mDNS, so an app that can only discover will
  never see it however many ports are open.
- **AirPlay is not routed at all.** Its control channel is TCP but its audio and
  timing are UDP/RTP, so routing the control port would negotiate a session that
  then plays nothing — worse than failing to connect.

Long-lived idle connections are fine: a WebSocket held open for a minute with no
traffic survives, which is the normal state of a control channel between
commands.

**Other limits.** The listener count per port is the concurrency limit for that
port — smoltcp has no accept queue, so a connection arriving with none free is
refused rather than queued. One peer at a time. DERP certificates are not
verified (see [Caveats](#caveats)).

## Layout

```
crates/tailscale-core/   no_std, sans-IO. Protocol state machines, zero I/O.
crates/lando-host/       std binary: runs the same core on a laptop.
crates/lando-fw/         no_std firmware for the Pico 2 W.
```

`tailscale-core` never touches a socket, a clock or an allocator, so the *same
compiled logic* runs under a debugger on a laptop and on a board that has
neither a debugger nor an OS. That split is the reason this was tractable: the
board has USB CDC logging and nothing else, and bare metal is a bad place to
discover that a length prefix is little-endian.

## Try it

On a laptop, no hardware required:

```sh
cargo test
echo 'tskey-auth-...' > .lando-authkey     # or omit for interactive login
cargo run -p lando-host
```

The node appears in your admin console. `LANDO_TRACE=1` dumps the HTTP/2
exchange — everything on the wire is inside Noise, so a packet capture shows
only ciphertext and this is the only way to watch the protocol.

On hardware:

```sh
make cyw43-firmware    # radio blobs, fetched rather than vendored
make flash             # reboots the board into its bootloader, then flashes
make console           # USB serial console
```

In the console, set `ssid`, `pass` and `key` (a tailnet pre-auth key), then
`save`. Credentials live in their own flash sector and never in the image, so
every board runs byte-identical firmware. `show` prints the current config and
`clear` erases it.

`make flash` works without anyone touching the board: the running firmware takes
`b` on its console as "hand yourself back to the bootloader". Without that, every
reflash needs a human holding BOOTSEL while replugging.

## Notes on the protocol

Tailscale treats this interface as internal and does not document it. The
findings that cost the most to establish, in case they save someone else the
time:

- **The control channel needs no TLS.** `POST /ts2021` on **port 80**, in the
  clear, Noise initiation base64'd into `X-Tailscale-Handshake`. Noise supplies
  confidentiality and authentication on top. This is what makes a client on a
  microcontroller tractable at all.
- **A streaming `MapRequest` is read-only.** With `Stream: true` and
  `Version >= 68` the server ignores `Hostinfo` and `Endpoints` entirely. A
  client that only long-polls goes *online* and yet publishes no endpoints, no
  relay and no connectivity data — with no error anywhere. Send those on a
  separate one-shot request (`Stream: false`, `OmitPeers: true`).
- **An early payload precedes HTTP/2.** After the handshake the server sends
  `\xff\xff\xffTS`, a 4-byte big-endian length, then JSON. Feed it to an HTTP/2
  parser and the connection desynchronises and hangs forever.
- **The record nonce is big-endian**, though Noise specifies little-endian. And
  WireGuard, using the same cipher and nonce layout, counts little-endian. The
  netmap's length prefix is little-endian too, while every other length on the
  control connection is big-endian.
- **An unparseable `IPNVersion` silently discards the whole `Hostinfo`.** No
  error; the struct simply never appears, and everything in it goes too.
- **disco is not optional.** A peer will not send WireGuard to an endpoint it
  has not validated with a disco pong, so a node that cannot answer disco is
  unreachable on every direct path regardless of its netmap. The symptom is
  silence at both ends.
- **WireGuard's `mac1` uses BLAKE2s in keyed mode, not HMAC** — while its KDF
  uses HMAC. Swapping them produces handshakes a peer drops without reply, which
  looks exactly like a firewall.
- **`derp1.tailscale.com` is not in region 1's mesh** (`derp1i`/`derp1h` are).
  The wrong node accepts you, completes its handshake, and routes nothing.
- **HPACK decoding is unnecessary.** Response HEADERS frames can be skipped
  whole; `SETTINGS_HEADER_TABLE_SIZE = 0` forbids the server from indexing,
  which makes that safe rather than merely convenient. `WINDOW_UPDATE`, however,
  is mandatory — the send window closes after 65535 bytes and stalls silently.

The embedded side had its own lessons, recorded in the code: a smoltcp send
buffer *is* the TCP window, so over an 80 ms relay a 768-byte buffer caps a
transfer at 9 KB/s; and a future cancelled by `select` loses everything in its
locals, which desynchronises a frame reader permanently if that is where the
parser state lives.

## Testing

Round-tripping a protocol against its own implementation proves self-consistency
and nothing else — every KDF and DH ordering could be uniformly wrong and the
tests would pass. So the ones that matter have a second opinion:

- BLAKE2s HMAC and KDF against vectors from Python's `hmac`/`hashlib`.
- The WireGuard handshake and transport against
  [boringtun](https://github.com/cloudflare/boringtun), in **both** directions —
  our initiator against its responder and vice versa. It is a dev-dependency and
  never reaches the firmware build.

```sh
cargo test                                                          # everything
cargo test -p tailscale-core --test interop_boringtun
cargo build --target thumbv8m.main-none-eabihf -p tailscale-core    # no_std check
```

## Caveats

**DERP certificates are not verified on the device.** `embedded-tls` has no
`no_std` certificate verification. It is defensible only because of what DERP
carries: no credential transits it — authentication is a NaCl box against the
node key — and every relayed byte is already WireGuard-encrypted end to end. A
man-in-the-middle gets ciphertext, traffic metadata and the ability to drop
packets; not decryption, forgery or access. The host binary verifies properly;
only the device makes this trade.

**The control protocol is unstable.** Tailscale treats it as internal and
changes it. This is a hobby project, not a supported client. If you want a
control plane you can pin, use
[Headscale](https://github.com/juanfont/headscale) — lando works against it too.

Prior art worth reading, both targeting ESP32:
[microlink](https://github.com/CamM2325/microlink) (C) and
[tailscale-esp32](https://github.com/0xdilo/tailscale-esp32) (Rust).

## License

MIT
