# opaque

OPAQUE, the augmented password-authenticated key exchange of
[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807), in Haskell, over
[libsodium](https://libsodium.org).

A client proves that it knows a password to a server that never sees the
password, neither at registration nor at login. The server keeps a
registration record per client. A thief of the records learns nothing that
lets them test a guess of the password without the server's long-term
secret, and even with it each guess costs a run of the key stretching
function. Every login agrees on a session key, and gives the client an export
key that only the client can compute and that is the same at every login.

## What it implements

- The suite **ristretto255, SHA-512, HKDF-SHA-512, HMAC-SHA-512**, with the
  **3DH** key exchange (RFC 9807, section 6.4), and the OPRF of
  [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497) in its OPRF mode
  (`modeOPRF`, suite `ristretto255-SHA512`).
- Registration (`registrationRequest`, `registrationResponse`,
  `finalizeRegistration`) and login (`clientStart`, `serverRespond`,
  `clientFinish`, `serverFinish`), with the RFC's names for each step.
- The **fake record** of section 6.3.2.2: `serverRespond` with no record
  answers with a fake record kept in the `ServerSetup`, so that an answer
  does not tell whether a client exists. The client then fails at
  `clientFinish` exactly as with a wrong password.
- The **key stretching function** is a parameter (`Ksf`): `Argon2id` with
  the passes and memory the application chooses (parallelism 1, a salt of 16
  zero bytes, a 64-byte output, through libsodium's `crypto_pwhash`), or
  `Identity`, which is no stretching and exists for the RFC's test vectors.
  The RFC recommends Argon2id with 2 GiB of memory and parallelism 4;
  libsodium supports parallelism 1 only, and an application running the
  client in a browser has to choose less memory. The application stores the
  parameters it used beside each record.
- The shared **context** string and the optional **identities** of both
  parties (`Config`, `Identities`); an identity left out stands for the
  party's public key, the RFC's default.
- **Encodings** of every message, record and state (`Encoding`), byte for
  byte as the RFC's structures, with the lengths and the group elements
  checked on decoding.
- **Constant-time** comparison of every MAC (`sodium_memcmp`).

The tests run the RFCs' test vectors for this suite (RFC 9807 appendix C.1.1,
C.1.2 and C.2.1; RFC 9497 appendix A.1.1), and round trips with real random
values, natively and as wasm32-wasi under Node.

## What it does not implement

- Other suites: P-256, P-384, P-521, decaf448, and the 3DH over Curve25519 of
  RFC 9807's vectors 3 and 4.
- The VOPRF and POPRF modes of RFC 9497.
- Any primitive. ristretto255, SHA-512, HMAC-SHA-512, Argon2id and the random
  numbers are libsodium's. HKDF (RFC 5869) and `expand_message_xmd` (RFC
  9380) are written here: each is a few lines of hashing and MACs, and
  libsodium 1.0.18 has no HKDF-SHA-512.
- Transport. The session key is yours to use; nothing here encrypts traffic.
- Wiping secrets from memory. The protocol's values are immutable
  `ByteString`s on GHC's heap, which the garbage collector may copy; only the
  buffers allocated for the C calls (HMAC's state) are wiped.

## Building

It needs libsodium 1.0.18 or later, the first with ristretto255, linked as
`-lsodium`. Natively that is the system's (`libsodium-dev` on Debian). For
GHC's WebAssembly backend it is a libsodium built for wasm32-wasi with the
wasi-sdk; point cabal at it with `extra-include-dirs` and `extra-lib-dirs`
for this package.

## Using it

```haskell
import Crypto.OPAQUE

-- once, on the server; keep the encoding secret
Right setup <- generateServerSetup

let config = Config {context = "my-app v1", ksf = Argon2id {opsLimit = 2, memLimit = 64 * 1024 * 1024}}
    cid = CredentialId "user-42" -- never changes for a record

-- registration
Right (cst, request) <- registrationRequest "password"                    -- client
let Right response = registrationResponse setup cid request               -- server
Right (record, exportKey) <- finalizeRegistration config cst response defaultIdentities -- client

-- login
Right (cst', ke1) <- clientStart "password"                                -- client
Right (sst, ke2) <- serverRespond config setup (Just record) cid ke1 defaultIdentities -- server
let Right (ke3, sessionKey, exportKey') = clientFinish config cst' ke2 defaultIdentities -- client
let Right sessionKey' = serverFinish sst ke3                               -- server
```
