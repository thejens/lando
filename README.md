# lando

**Reach everything on your home network from anywhere — with nothing exposed to
the internet, and nothing to pay for.**

Plug a $7 microcontroller into a spare USB charger. Configure it once. From then
on your phone on cellular, or your laptop at work, can talk to your amplifier,
your router's admin page, your speakers — every device on that network — exactly
as if you were sitting at home.

```
phone on 5G ──encrypted──▶ relay ──▶ lando ──▶ 192.168.1.50
                                               anything on the LAN
```

## Why you'd want this

Getting at a device on your home network from outside normally costs you one of
these:

| The usual way | What it costs you |
|---|---|
| Port forwarding | Your device is now on the public internet, being scanned |
| Dynamic DNS | Another account, another thing that silently expires |
| A VPN server | A machine to run, patch, and keep running |
| A vendor's cloud | A subscription, and your data through someone else's servers |
| A Raspberry Pi | 10× the price, an SD card that will corrupt itself, an OS to maintain |

lando is none of them. It joins your private Tailscale network as an ordinary
device and quietly bridges the rest of your home onto it.

- **Nothing is exposed.** Every connection it makes is outbound. Your router is
  never touched, no ports are opened, and there is nothing on the public
  internet to find or attack.
- **Nothing to run.** No server, no container, no account beyond Tailscale's
  free tier. It is a sealed device that boots in five seconds and stays up.
- **Nothing to configure per device.** It advertises your whole network, so you
  use the same addresses you already use at home — no per-device tunnels, no
  port-forward table to maintain.
- **It sips power.** A microcontroller on a phone charger, not a computer in a
  cupboard.
- **Your traffic stays yours.** Encrypted end to end between your phone and this
  device, authenticated by your own network's identity. No vendor in the middle.

It replaces an earlier version of this project that did the same job by holding a
connection open to a Cloudflare Worker — a hosted dependency, a second codebase,
and somewhere a device credential had to live. A private network already solves
identity, encryption and getting through your router, so none of that needs to
exist.

## What you can actually do with it

Once it is on your network, from anywhere in the world:

```sh
# your router's admin page, from a phone on cellular
open http://192.168.1.1/

# your amplifier's API, its vendor app, its web interface
curl http://192.168.1.50:8080/...

# and find out what is even on the network, without being on it
dig @lando -p 5353 _services._dns-sd._udp.local PTR
```

That last one matters more than it looks: normally nothing outside your home can
enumerate what is inside it. lando answers discovery on behalf of the network. In
one house it found 22 kinds of service — Spotify Connect, Google Cast, AirPlay,
Matter, a lighting system — and resolved the amplifier's own control protocol to
the exact host and port its app uses.

Vendor apps generally work, including ones that hold a connection open for hours
between commands. Two things decide whether a given app is happy, and both are
checkable in advance — see below.

## Limits

Stated plainly, because the shape of what this cannot do is as useful as what it
can.

- **Your app must let you type an address.** Discovery works, but only when
  something asks for it. An app that can only *browse* for devices — the Google
  Home app, most Cast and AirPlay clients — will not find anything, and no
  amount of work here changes that. See [Discovery](#discovery).
- **TCP only.** Protocols that carry audio over UDP, AirPlay among them, do not
  cross.
- **Ports are declared, not discovered.** Only listed ports are bridged, and the
  number of listeners on a port is how many connections it can carry at once.
  Currently routed: `80`, `84`, `443`, `8008`, `8009`, `8080`, `37193`. Adding
  one is a single line.
- **One person at a time.** It serves a single peer, not a household.
- **Fast enough to control things, not to move files.** Measured on a 172 KB
  download: 2.8 s over a direct path, 8.4 s via a relay. Every byte is encrypted
  twice, in software, on a 150 MHz chip.
- **It is a hobby project.** It speaks an interface Tailscale treats as internal
  and does not promise to keep stable. It works, it is tested against the real
  thing, and it will occasionally need updating when that changes.

## Discovery

```sh
dig @lando -p 5353 _services._dns-sd._udp.local PTR
```

That lists the service types on the far network; browsing one and resolving it
gives a host and port to connect to.

**It has to be asked directly, and that is a hard limit rather than a shortcut.**
Three separate things stop an ordinary browse from reaching this device, and only
the first is Tailscale's:

1. A private network like this carries no multicast, and discovery is multicast.
2. Your phone would not send it there anyway — multicast goes out over the local
   wireless link, not the tunnel.
3. `.local` names are reserved for local-link discovery in every mainstream
   operating system, so they cannot be pointed at a remote server either.

So a phone's Cast browse will never arrive here. What does work is anything that
can be handed an address: a script, a home-automation server, `dig`. That is the
ceiling — but it is the difference between finding nothing and listing
everything.

## Getting one running

You need a Raspberry Pi Pico 2 W, a USB cable, and a free Tailscale account.

```sh
make cyw43-firmware    # wireless firmware, fetched rather than bundled
make flash             # builds and flashes over USB
make console           # talk to it
```

In the console set `ssid`, `pass` and `key` (a Tailscale pre-auth key), then
`save`. Credentials live in their own area of flash and never in the firmware
image, so every board runs byte-identical code and the image carries no secrets.
`show` prints the configuration and `clear` erases it.

Then approve its route in the Tailscale admin console, and it is done.
Reflashing never needs anyone to touch the board — it takes `b` on its console
as "hand yourself back to the bootloader".

## For developers

No Tailscale daemon, no Go runtime, no operating system: the wire protocol
implemented from scratch on bare metal, in 416 KB of the chip's 512 KB of RAM.
As far as I can tell it is the smallest complete Tailscale node there is —
control plane, WireGuard, endpoint discovery, relay support and a TCP proxy on a
microcontroller with no memory management unit, no allocator, and nothing
underneath it.

```
crates/tailscale-core/   no_std, sans-IO. Protocol state machines, zero I/O.
crates/lando-host/       std binary: runs the same core on a laptop.
crates/lando-fw/         no_std firmware for the Pico 2 W.
```

`tailscale-core` never touches a socket, a clock or an allocator, so the *same
compiled logic* runs under a debugger on a laptop and on a board that has
neither a debugger nor an OS. That split is why this was tractable: the board has
a USB serial log and nothing else, and bare metal is a bad place to discover that
a length prefix is little-endian.

Run it on a laptop, no hardware required:

```sh
cargo test
echo 'tskey-auth-...' > .lando-authkey    # or omit, for interactive login
cargo run -p lando-host
```

`LANDO_TRACE=1` dumps the HTTP/2 exchange. Everything on the wire is inside
Noise, so a packet capture shows only ciphertext — this is the only way to watch
the protocol.

### Notes on the protocol

Tailscale treats this interface as internal and does not document it. The
findings that cost the most to establish:

- **The control channel needs no TLS.** `POST /ts2021` on **port 80**, in the
  clear, with the Noise handshake base64'd into a header. Noise supplies
  confidentiality and authentication on top. This is what makes a client on a
  microcontroller tractable at all.
- **A streaming `MapRequest` is read-only.** With `Stream: true` and
  `Version >= 68` the server ignores `Hostinfo` and `Endpoints` entirely, so a
  client that only long-polls goes *online* while publishing no endpoints, no
  relay and no connectivity data — with no error anywhere. Send those on a
  separate one-shot request.
- **An early payload precedes HTTP/2.** After the handshake the server sends
  `\xff\xff\xffTS`, a big-endian length, then JSON. Feed it to an HTTP/2 parser
  and the connection desynchronises and hangs forever.
- **The record nonce is big-endian**, though Noise specifies little-endian — and
  WireGuard, with the same cipher and nonce layout, counts little-endian.
- **An unparseable `IPNVersion` silently discards the whole `Hostinfo`.**
- **Endpoint discovery is not optional.** A peer will not send WireGuard traffic
  to an endpoint it has not validated, so a node that cannot answer a disco ping
  is unreachable on every direct path regardless of what its netmap says.
- **WireGuard's `mac1` uses BLAKE2s in keyed mode, not HMAC** — while its KDF
  uses HMAC. Swapping them produces handshakes a peer drops without reply, which
  looks exactly like a firewall.
- **`derp1.tailscale.com` is not in relay region 1's mesh.** The wrong node
  accepts you, completes its handshake, and routes nothing.
- **`WINDOW_UPDATE` is mandatory** — the send window closes after 65535 bytes and
  the connection stalls silently. HPACK *decoding*, by contrast, can be skipped
  entirely.

The embedded side had its own, recorded in the code: a send buffer *is* the TCP
window, so over an 80 ms relay a 768-byte buffer caps a transfer at 9 KB/s; and a
future cancelled by `select` loses everything in its locals, which desynchronises
a frame reader permanently if that is where the parser state lives.

### Testing

Round-tripping a protocol against its own implementation proves self-consistency
and nothing else — every KDF and DH ordering could be uniformly wrong and the
tests would still pass. So the ones that matter have a second opinion:

- BLAKE2s HMAC and KDF against vectors from Python's `hmac`/`hashlib`.
- The WireGuard handshake and transport against
  [boringtun](https://github.com/cloudflare/boringtun), in **both** directions.
  It is a dev-dependency and never reaches the firmware.

```sh
cargo test                                                          # everything
cargo test -p tailscale-core --test interop_boringtun
cargo build --target thumbv8m.main-none-eabihf -p tailscale-core    # no_std check
```

### Security note

**Relay certificates are not verified on the device.** `embedded-tls` has no
`no_std` certificate verification. It is defensible only because of what that
connection carries: no credential crosses it — authentication is a sealed box
against the node key — and every relayed byte is already encrypted end to end. A
man-in-the-middle gets ciphertext, traffic metadata, and the ability to drop
packets; not decryption, forgery, or access. The laptop binary verifies properly;
only the device makes this trade.

Prior art worth reading, both targeting ESP32:
[microlink](https://github.com/CamM2325/microlink) (C) and
[tailscale-esp32](https://github.com/0xdilo/tailscale-esp32) (Rust).
If you want a control plane you can pin, lando also works against
[Headscale](https://github.com/juanfont/headscale).

## License

MIT
