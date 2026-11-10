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

What it is tested against is under [Testing](#testing).

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
- **wasm32-wasi has no `mlock` and no guard pages.** There `sodium_malloc`
  is `posix_memalign` with WASI's 64 KiB page, about 320 KiB per secret, and
  locks nothing. The memory is still zeroed, but in a browser the whole
  linear memory is readable by any script on the page.
- Zeroing is not tested for timing or with a debugger; no OPAQUE
  implementation tests it.

## Building

It builds natively, with GHC 9.10 to 9.14 (CI builds and tests it on
9.10.3, 9.12.4 and 9.14.1), and for GHC's WebAssembly backend with the flag
`wasm-libsodium` (CI: `wasm32-wasi-ghc` 9.14.1). It is not buildable for
the JavaScript backend, which links no C library.

### Natively

It needs libsodium 1.0.19 or later, found through `pkg-config`, for its
HKDF-SHA-512:

```sh
pkg-config --modversion libsodium   # 1.0.19 or later
cabal build
```

Debian 12 and Ubuntu 24.04 ship libsodium 1.0.18. On such a machine there
are two ways:

- Build a newer libsodium from source with the script here, and point
  `pkg-config` at it. It builds one pinned release, checked against its
  checksum, as a static library under `.libsodium`, in under a minute:

  ```sh
  sh scripts/libsodium.sh install
  export PKG_CONFIG_PATH="$PWD/.libsodium/lib/pkgconfig:$PKG_CONFIG_PATH"
  cabal build
  ```

- Or build against the system's library with the cabal flag
  `older-libsodium` (off by default): HKDF is then a Haskell polyfill over
  libsodium's HMAC-SHA-512, which the test suite checks against libsodium's
  own HKDF in every build without the flag.

  ```sh
  cabal build -folder-libsodium
  ```

### WebAssembly

With the cabal flag `wasm-libsodium` (off by default) the package builds
for wasm32-wasi over a libsodium compiled for it. Without the flag it is
not buildable there, so that a program for the browser cannot come to
depend on it by accident: read [the caveats](#memory) first.

It needs GHC's WebAssembly toolchain,
[ghc-wasm-meta](https://gitlab.haskell.org/haskell-wasm/ghc-wasm-meta),
which brings `wasm32-wasi-ghc` and the wasi-sdk. libsodium publishes no
build for wasm32-wasi, so the script here compiles the same pinned release
with the wasi-sdk, under `.libsodium-wasm`:

```sh
. ~/.ghc-wasm/env
sh scripts/libsodium.sh install-wasm
cabal --project-file=cabal-wasm.project build all $(sh scripts/libsodium.sh env-wasm)
```

`env-wasm` prints `--extra-lib-dirs=…` and `--extra-include-dirs=…`: cabal
runs the host's `pkg-config`, which knows nothing of a wasm library, so the
package links `-lsodium` there and has to be told where it is. In a project
of your own, turn the flag on for the package and give the same two
directories:

```cabal
package opaque-hs
  flags: +wasm-libsodium
  extra-lib-dirs: /path/to/.libsodium-wasm/lib
  extra-include-dirs: /path/to/.libsodium-wasm/include
```

The result is a WASI module: it runs under `wasmtime`, under Node, and in
a browser with a WASI shim. Random numbers come from WASI's `random_get`.

A browser client that does not need this package's server, its API or its
tests' guarantees may be better served by an OPAQUE implementation built
for the browser, such as
[`@serenity-kit/opaque`](https://github.com/serenity-kit/opaque), which
this package is tested against.

## Testing

```sh
npm ci            # once: @serenity-kit/opaque, for the tests against it
cabal test opaque-test
```

`opaque-test` runs:

- the RFCs' test vectors for this suite (RFC 9807 appendix C.1.1, C.1.2 and
  C.2.1; RFC 9497 appendix A.1.1) and RFC 9380's `expand_message_xmd`
  vectors;
- HKDF-SHA-512 and Argon2id against OpenSSL's answers;
- the cases other OPAQUE implementations test beyond the vectors, QuickCheck
  properties of the encodings, and round trips with real random values;
- **this package against `@serenity-kit/opaque`** (opaque-ke compiled to
  WebAssembly, the client a browser would use), under Node: its client with
  this package's server, this package's client with its server, and a
  registration by one client with a login by the other. Without Node or
  without `npm ci` these tests are skipped, and say so.

For wasm32-wasi the same test suite is one module, run under `wasmtime`
(or Node):

```sh
wasmtime run "$(find dist-newstyle -name opaque-test.wasm)"
```

There it runs everything but the tests against `@serenity-kit/opaque`,
which drive a Node process and a WASI program starts none: one pending
example stands for them.

A second test suite compares the package with a reference implementation,
[libopaque](https://github.com/stef/libopaque) (in C, over
[liboprf](https://github.com/stef/liboprf) and libsodium):

```sh
sh scripts/reference.sh install
export PKG_CONFIG_PATH="$PWD/.reference/lib/pkgconfig:$PKG_CONFIG_PATH"
cabal test opaque-reference -freference
```

`opaque-reference` runs, on random passwords, identities and contexts:

- the OPRF's functions one by one, against liboprf;
- a whole registration and a whole login with the same random values on
  both sides: every message, the record, the session key and the export key
  must be the same bytes, with Argon2id as libopaque stretches (2 passes,
  64 MiB);
- each side's client against the other's server, with real random values.

`scripts/reference.sh` fetches libopaque and liboprf at two pinned commits
and builds them under `.reference`. At those commits their own programs
reproduce the test vectors of RFC 9807 and RFC 9497. Both libraries are
under the LGPL, version 3 or later: nothing of them is in this repository
or in the package, and they are linked only into that test program, which
is not distributed.

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
