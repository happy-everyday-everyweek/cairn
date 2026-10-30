# Cairn

A small C11 library for peer discovery, pairing, connection and end-to-end
encrypted transfer over a local network. Android to Android is the main target;
Linux, Windows and macOS build from the same sources.

The name is a stack of stones marking a path.

## What it does

Two devices find each other with a beacon, agree on a session key, show a six
digit code both humans compare, and then exchange messages or files. A dropped
connection does not restart a file transfer: it resumes at the first chunk the
peer never confirmed.

## What it deliberately does not do

A single rule decides what enters this library: if an application can implement
it without the library, the library does not ship it. So there is no file I/O, no
argument parsing, no logging framework, no thread pool, no event loop, no UI and
no generic serialisation. What is left is the part an application cannot
reasonably write itself: the cryptographic primitives, the handshake and key
schedule, the frame format, the resumable transfer state machine, the NAT
traversal state machine, and the platform seams where Bluetooth and Wi-Fi Direct
differ.

The library also owns no sockets. It takes frames in and produces frames out,
which is why a Bluetooth link, a Wi-Fi Direct group, a UDP socket and two nodes in
a test all drive the same code.

## Design notes worth knowing before reading the code

Forward secrecy does not depend on the static identity key. A real DH ratchet runs
after the handshake: every eight messages the sender advertises a fresh ratchet
public key and folds a new DH output into the root key, and the chain key advances
after every single message. A leaked chain key therefore exposes one message, not
a conversation.

Post quantum protection is mixed in during the handshake rather than bolted on
later. ML-KEM-768 contributes a shared secret alongside the three X25519 outputs,
so recorded traffic stays confidential if X25519 falls to a future quantum machine.

The layered wrapping is obfuscation, not encryption. It makes the wire bytes look
uniform and hides the exact plaintext length in 64 byte buckets, but the secrecy
of the payload rests entirely on the outer AEAD. The header says so, so nobody
mistakes it for a confidentiality mechanism.

## Building

```
cmake -S . -B build
cmake --build build -j4
./build/cairn_tests
```

Requirements: a C11 compiler and CMake 3.16 or newer. Nothing else. The two
cryptographic libraries are copied into `vendor/`, so there is no package manager
step and no network access during a build.

The test binary needs no hardware: Bluetooth and Wi-Fi Direct sit behind vtables
that the tests fill with in-memory fakes, and the STUN parser is fed packets built
by hand from RFC 5389 rather than a live server.

Current state: 113 tests, all passing, zero compiler warnings under
`-Wall -Wextra`.

## Command line demo

```
./build/cairn_cli key                    # this device's fingerprint
./build/cairn_cli selftest               # two nodes, one real UDP socket
./build/cairn_cli listen 9000            # answer handshakes
./build/cairn_cli send 192.168.1.42 9000 "hello"
./build/cairn_cli put  192.168.1.42 9000 somefile.bin
```

`selftest` is the quickest way to see the whole stack run: it creates two nodes,
passes the handshake frames through a loopback socket, and prints whether both
sides reached the ready state and whether the message arrived.

## Android demo

`android/` contains a small application that discovers peers, handshakes, sends
messages and streams a synthetic file. The JNI bridge exposes only the protocol;
the socket, the permissions and the UI stay in Kotlin.

A debug APK is built on every push by GitHub Actions and attached to the workflow
run as an artifact, so no local Android SDK is needed to try it.

## API

| Header | Responsibility |
| --- | --- |
| `cairn/crypto.h` | BLAKE2b, XChaCha20-Poly1305, X25519, Ed25519, ML-KEM-768 |
| `cairn/nested.h` | Layered wrapping from a passphrase |
| `cairn/identity.h` | Identity, fingerprint, six digit safety code |
| `cairn/session.h` | Handshake, DH ratchet, replay rejection |
| `cairn/wire.h` | Frame encoding, decoding, checksum |
| `cairn/transfer.h` | Chunking, acknowledgements, resume |
| `cairn/discovery.h` | Beacon, neighbour table |
| `cairn/ble.h` | Bluetooth LE backend vtable |
| `cairn/p2p.h` | Wi-Fi Direct backend vtable |
| `cairn/nat.h` | STUN, hole punching, relay fallback |
| `cairn/node.h` | Everything assembled into a node |
| `cairn/platform.h` | Clock, sleep, host name |

`docs/SEAMS.md` is the contract the tests hold the implementation to, and
`docs/DESIGN.md` records why each module exists.

## Cryptographic provenance

No primitive is handwritten. Monocypher provides X25519, Ed25519, BLAKE2b and
XChaCha20-Poly1305; PQClean provides ML-KEM-768. Both are vendored, and every
primitive is checked against an independent implementation: RFC 7693 vectors and
Python `hashlib` for BLAKE2b, libsodium vectors for the AEAD, RFC 7748 for X25519,
RFC 8032 for Ed25519. See `THIRD_PARTY.md` for the two upstream licences.

This is a young library. It has not been audited. Treat it as a solid
implementation of known constructions, not as a guarantee.

## Licence

MIT. See `LICENSE`. Vendored code keeps its own licence, described in
`THIRD_PARTY.md`.