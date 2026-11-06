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
computes them, with QuickCheck properties of the encodings, natively and as
wasm32-wasi.
