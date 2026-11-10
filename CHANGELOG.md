# Changelog

## Unreleased

The first version. OPAQUE (RFC 9807) with the suite ristretto255, SHA-512
and 3DH, its OPRF (RFC 9497, `modeOPRF`, `ristretto255-SHA512`), the fake
record for clients with no record, a key stretching function chosen by the
application (Argon2id through libsodium, or none for test vectors), and
encodings of every message, record and state. The client refuses an
evaluated element equal to its own blinded one, and every function refuses
a password, an identity or a context too long for the RFC's two-byte
lengths. Tested against the RFCs' test vectors, RFC 9380's
`expand_message_xmd` vectors and HKDF-SHA-512 and Argon2id as OpenSSL
computes them, with QuickCheck properties of the encodings. Secrets are
kept in memory the package zeroes: `sodium_malloc` for the states and keys,
a scratch buffer zeroed after each step for intermediate values, and
`scrub` to zero a value at once. HKDF is libsodium's (1.0.19 or later); the
flag `older-libsodium`, off by default, builds against 1.0.18 with a Haskell
HKDF, which the test suite compares with libsodium's own wherever the flag
is off.

The package is named `opaque-hs` and has a repository of its own; it was
the package `opaque` of the wiki at Swordlash/wiki. Its tests compare it
with two other implementations: `@serenity-kit/opaque` under Node, and
libopaque with liboprf, built from source by `scripts/reference.sh`, in the
test suite `opaque-reference` (flag `reference`), step by step and with the
same random values. `scripts/libsodium.sh` builds a libsodium new enough on
a machine whose own is 1.0.18.

The flag `wasm-libsodium`, off by default, builds the package for GHC's
WebAssembly backend over a libsodium compiled for wasm32-wasi, which
`scripts/libsodium.sh install-wasm` builds with the wasi-sdk. Without the
flag the package is not buildable there. The test suite runs as a WASI
module under `wasmtime`, all of it but the tests that drive Node. The
package is not buildable for the JavaScript backend.
