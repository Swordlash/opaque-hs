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
- **Secrets in memory it zeroes**: see [Memory](#memory).

The tests run the RFCs' test vectors for this suite (RFC 9807 appendix C.1.1,
C.1.2 and C.2.1; RFC 9497 appendix A.1.1), RFC 9380's `expand_message_xmd`
vectors, HKDF-SHA-512 and Argon2id against OpenSSL, the cases other OPAQUE
implementations test beyond the vectors, QuickCheck properties, and round
trips with real random values.

## What it does not implement

- Other suites: P-256, P-384, P-521, decaf448, and the 3DH over Curve25519 of
  RFC 9807's vectors 3 and 4.
- The VOPRF and POPRF modes of RFC 9497.
- Any primitive. ristretto255, SHA-512, HMAC-SHA-512, HKDF-SHA-512,
  Argon2id and the random numbers are libsodium's. `expand_message_xmd`
  (RFC 9380) is written here over libsodium's SHA-512, because libsodium has
  no hash-to-group for ristretto255 that takes a domain separation tag
  (`crypto_core_ristretto255_from_hash` is the map after it). With the flag
  `older-libsodium`, HKDF is a Haskell polyfill over libsodium's HMAC, for
  libsodium 1.0.18, which has no HKDF.
- Transport. The session key is yours to use; nothing here encrypts traffic.

## Memory

Every value derived from the password or from a private key is kept out of
GHC's ordinary `ByteString`s, whose buffers the collector frees without
zeroing them:

- **Long-lived secrets** (the `ServerSetup`'s OPRF seed and private key, the
  client's registration and login states with the password copied into them,
  the server's login state, the `SessionKey` and the `ExportKey`) are in
  libsodium's `sodium_malloc` memory: outside GHC's heap, between guard
  pages, locked with `mlock`, and zeroed by `sodium_free` when the value is
  collected. `scrub` zeroes one at once, for a caller that knows its
  lifetime has ended.
- **Intermediate values** of a step (the OPRF's output, the stretched output,
  the randomized password, the masking, MAC and export keys, the envelope's
  seed, derived private keys, the Diffie-Hellman products, HKDF's keys, the
  per-client OPRF key, the pad) are in one pinned scratch buffer per step,
  zeroed with `sodium_memzero` when the step ends, on its error paths too.
  libsodium's hash and MAC states are zeroed after each call.
- **Public values** (messages, public keys, nonces, MACs that are sent,
  records) are ordinary `ByteString`s.

What it does not protect:

- **The caller's copies.** The password the caller passes in, and the
  encoding of a state, the setup or a key (`encode`), are the caller's
  `ByteString`s. In a browser the password is a JavaScript string, which
  nothing can zero.
- **Locking can fail.** `mlock` is limited by `RLIMIT_MEMLOCK` (8 MiB under
  systemd by default), which a server holding many login states can reach.
  A failure to lock is not an error: the memory is used unlocked, and may
  be swapped out.
- Zeroing is not tested for timing or with a debugger; no OPAQUE
  implementation tests it.

## Building

It needs libsodium 1.0.19 or later, found through `pkg-config`, for its
HKDF-SHA-512. The cabal flag `older-libsodium` (off by default) is for a
machine that must build against an older system library, 1.0.18 (Debian 12's
and Ubuntu 24.04's `libsodium-dev`): HKDF is then a Haskell polyfill over
libsodium's HMAC-SHA-512, which the test suite checks against libsodium's own
HKDF in every build without the flag. The wiki builds without it, against a
libsodium of its toolchain's, built from source. It builds natively only. It is not buildable for wasm32-wasi: there
`sodium_malloc` would have no `mlock` and no guard pages, and cost about
320 KiB per secret (WASI's 64 KiB pages), and any script on a page can read
a wasm program's whole memory. A browser client is better served by an
OPAQUE implementation built for it (the wiki uses `@serenity-kit/opaque`,
which interoperates with this one).

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
scrub sst                                                                  -- server, once done
```
