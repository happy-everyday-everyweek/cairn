# Cairn

[![build](https://github.com/happy-everyday-everyweek/cairn/actions/workflows/build.yml/badge.svg)](https://github.com/happy-everyday-everyweek/cairn/actions/workflows/build.yml)

Peer discovery, pairing by a short code, and end-to-end encrypted transfer in C11.
Android to Android is the main target; Linux, Windows and macOS build from the same
sources. Every push is built and tested on all four by GitHub Actions, and the debug APK
comes out as a workflow artifact.

Two devices find each other, the user types the same short code on both, and from then
on anything sent between them is encrypted. Files resume if the link drops. And for the
case where both devices are not awake at once, the same two devices can exchange an
offline bundle through a cloud drive instead.

## The whole API

Twenty-seven functions across `cairn.h` and `bundle.h`, and eleven of them cover the
everyday path.

```c
#include "cairn/cairn.h"

cairn_io io = { .on_message = on_message, .on_chunk = on_chunk, .on_ready = on_ready };
cairn_node *n = cairn_open("my phone", &io);

/* One side shows a code and waits, the other joins with the same code. */
if (cairn_pair_wait(n, "123456", 30000) == CAIRN_OK)
    cairn_send(n, "hello", 5);

for (;;) cairn_poll(n, 1000);   /* callbacks fire here */
cairn_close(n);
```

Pairing is symmetric: `cairn_pair_wait` and `cairn_pair_join` are the same work with
different intent, so neither side has to know who is the client. Both return `CAIRN_OK`
or an error, and both block until they do.

Files are just as plain:

```c
cairn_send_file(n, total_bytes);
while (!cairn_transfer_done(n)) {
    size_t got = fread(buf, 1, sizeof buf, fp);
    cairn_send_chunk(n, buf, got, 5000);   /* blocks for the ack */
}
```

## The pairing code actually binds the session

This is the part worth being precise about, because a code that only the UI checks is
security theatre.

The code is folded into the label that keys both confirmation tags of the handshake.
Device A computes `MAC(root_key, "accept|123456")`, device B computes
`MAC(root_key, "accept|654321")`. Different digits give different tags, the tag check
fails, and the handshake dies with `CAIRN_ERR_AUTH`. Nobody watching the traffic can
produce a matching tag either, because producing one needs the root key, which needs the
X25519 and ML-KEM secrets.

The guarantee is therefore sharper than "the codes must match": a wrong code means no
session, and an eavesdropper means no session, through the same failure path.

`tests/test_pair.c` states it directly: same code connects, different code does not,
one-sided code does not, and clearing the code returns to the unbound behaviour.

## Offline bundles

To hand a file over through something that is not a live link — a cloud drive, a USB
stick, an email attachment — seal it to the recipient's public key:

```c
uint8_t bundle[cairn_bundle_size(len)];
size_t out_len;
cairn_seal(bundle, sizeof bundle, &out_len, &me, &their_pubkey, plain, len);
```

Later, on the other device, with no network:

```c
cairn_unseal(plain, sizeof plain, &plain_len, &me, bundle, bundle_len);
```

The key is a Diffie-Hellman between a one-time X25519 key made for that bundle and the
recipient's static key. The sender throws its one-time secret away immediately, so the
file on the cloud drive cannot be opened by the cloud provider, by the sender later, or
by any other device — only by the one holding the matching static key.

For large files, `cairn_bundle_begin` / `cairn_bundle_chunk` / `cairn_bundle_sign` let
you stream chunk by chunk to disk instead of holding the plaintext in memory. Every chunk
carries its own tag with its index bound in, so a flipped bit is caught and localised and
chunks cannot be reordered or dropped. The whole bundle also carries an Ed25519 signature,
so a modified download is refused before any decryption starts.

## What it deliberately does not do

One rule decides what enters the library: if an application can implement it without the
library, the library does not ship it. No file I/O, no argument parsing, no logging, no
thread pool, no UI. `cli/main.c` shows what an application layer looks like: a third of it
is argument parsing, and the protocol calls are one line each.

The library does own one socket now, because pairing by code needs to broadcast a beacon
without the caller arranging a transport. If you want to own the socket yourself, the
engine underneath (`cairn/protocol.h`) does exactly that and drives the same code path the
tests use.

## Building

```
cmake -S . -B build
cmake --build build -j4
./build/cairn_tests
```

A C11 compiler and CMake 3.16. Nothing else: both cryptographic libraries are copied into
`vendor/`, so there is no package manager step and no network access during a build.

The tests need no hardware — Bluetooth and Wi-Fi Direct sit behind vtables filled with
in-memory fakes, and the STUN parser is fed packets built by hand from RFC 5389. The one
test that needs a real network path is the two-node pairing case: it opens two sockets on
the same host. Hosts that will not deliver a datagram from a socket to another socket on
loopback get a SKIP with the reason, never a pass.

Current state: 133 tests, all passing, zero compiler warnings under `-Wall -Wextra`, on
Linux, Windows and macOS.

The Android demo is built by `gradle :app:assembleDebug` in CI, because the repository
carries no wrapper and the SDK, NDK and CMake all come from the runner. Each run publishes
`cairn-android-debug` as an artifact, and a `v*` tag also attaches the APK to the release.

## Command line

```
./build/cairn_cli key                        this device's fingerprint
./build/cairn_cli pair 123456                wait for a peer, 30 s
./build/cairn_cli send 123456 "hello"        pair, then send one message
./build/cairn_cli put  123456 file.bin       pair, then send a file
./build/cairn_cli seal recipient in out      write an offline bundle
./build/cairn_cli open identity in out       open an offline bundle
```

Two shells on the same network, `pair 123456` in one and `send 123456 hi` in the other, is
the shortest way to see it work.

## Design notes

Forward secrecy does not rest on the static identity key. A real DH ratchet runs after the
handshake: every eight messages the sender advertises a fresh ratchet key and folds a new
DH output into the root, and the chain key advances after every single message. A leaked
chain key exposes one message, not a conversation.

Post quantum protection is mixed in during the handshake. ML-KEM-768 contributes a shared
secret alongside the three X25519 outputs, so recorded traffic stays confidential if X25519
falls to a future quantum machine.

The layered wrapping in `cairn/nested.h` is obfuscation, not encryption. The header says so.

## Layers

| Header | Responsibility |
| --- | --- |
| `cairn/cairn.h` | Facade: open, pair, send, poll, close |
| `cairn/bundle.h` | Offline bundles, sealed to one recipient |
| `cairn/protocol.h` | Engine: frames in, frames out, no socket |
| `cairn/session.h` | Handshake, DH ratchet, replay rejection |
| `cairn/identity.h` | Identity, fingerprint, six digit safety code |
| `cairn/transfer.h` | Chunking, acknowledgements, resume |
| `cairn/wire.h` | Frame encoding, decoding, checksum |
| `cairn/discovery.h` | Beacon, neighbour table |
| `cairn/nat.h` | STUN, hole punching, relay fallback |
| `cairn/ble.h` / `cairn/p2p.h` | Bluetooth LE and Wi-Fi Direct backends |
| `cairn/crypto.h` | BLAKE2b, XChaCha20-Poly1305, X25519, Ed25519, ML-KEM-768 |
| `cairn/nested.h` | Layered obfuscation from a passphrase |
| `cairn/platform.h` | Clock, sleep, host name |

`docs/SEAMS.md` is the contract the tests hold the code to.

## Cryptographic provenance

No primitive is handwritten. Monocypher provides X25519, Ed25519, BLAKE2b and
XChaCha20-Poly1305; PQClean provides ML-KEM-768. Both are vendored, and every primitive is
checked against an independent implementation: RFC 7693 vectors and Python `hashlib` for
BLAKE2b, libsodium vectors for the AEAD, RFC 7748 for X25519, RFC 8032 for Ed25519. See
`THIRD_PARTY.md`.

This library has not been audited. Treat it as a careful implementation of known
constructions, not as a guarantee.

## Licence

MIT. See `LICENSE`. Vendored code keeps its own licence, described in `THIRD_PARTY.md`.