# Third party code

Cairn is MIT licensed. Two cryptographic libraries are copied into `vendor/`
rather than linked, so that a checkout builds with no package manager and every
byte that runs is reviewable in the tree. Both are licence compatible with MIT,
but their notices must travel with the code.

## Monocypher

Files: `vendor/monocypher/*`

Provides X25519, Ed25519, BLAKE2b and XChaCha20-Poly1305.

Dual licensed, `BSD-2-Clause OR CC0-1.0`. The full text of both licences is in
the header comment of `vendor/monocypher/monocypher.c`; the BSD 2-clause form is
the fallback when CC0 is not usable in a jurisdiction.

Copyright (c) 2017-2020, Loup Vaillant. All rights reserved.

Upstream: https://monocypher.org

## PQClean

Files: `vendor/pqclean/mlkem768/*`, `vendor/pqclean/fips202/*`,
`vendor/pqclean/common/*`

Provides ML-KEM-768 (Kyber) and the FIPS 202 permutation it builds on.

Public domain, CC0. The declared licence text is in
`vendor/pqclean/mlkem768/LICENSE`. For Keccak and AES, PQClean uses public
domain code whose authors are credited in the header of each file.

Upstream: https://github.com/PQClean/PQClean

## Note on the wrapper

`src/crypto/cairn_crypto.c` is the only file that calls into these two
libraries. Everything above it uses the `cairn_*` API, which is MIT licensed
like the rest of the project.