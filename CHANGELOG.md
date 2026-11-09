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
is off. Native only: not buildable for wasm32-wasi.
