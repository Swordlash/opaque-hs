# Changelog

## Unreleased

The first version. OPAQUE (RFC 9807) with the suite ristretto255, SHA-512
and 3DH, its OPRF (RFC 9497, `modeOPRF`, `ristretto255-SHA512`), the fake
record for clients with no record, a key stretching function chosen by the
application (Argon2id through libsodium, or none for test vectors), and
encodings of every message, record and state. Tested against the RFCs' test
vectors natively and as wasm32-wasi.
