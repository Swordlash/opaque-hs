# opaque-hs

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
- **The client alone, for a browser**: on GHC's WebAssembly and JavaScript
  backends the module `Crypto.OPAQUE.Client` has the client's four steps
  under the same names and types, and calls
  [`@serenity-kit/opaque`](https://github.com/serenity-kit/opaque) for them:
  see [The client for a browser](#the-client-for-a-browser).

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
- **The client for a browser zeroes little.** On the WebAssembly and
  JavaScript backends without libsodium, the password and serenity-kit's
  state are JavaScript strings, which are immutable: `scrub` drops them
  and the engine frees them when it will. A `SessionKey` and an
  `ExportKey` are bytes `scrub` zeroes, but serenity-kit returned them as
  strings first. Nothing is locked. `Crypto.OPAQUE.Client.WebCrypto` keeps
  the export key out of the program altogether, as a WebCrypto key that
  cannot be exported.
- Zeroing is not tested for timing or with a debugger; no OPAQUE
  implementation tests it.

## Building

It builds in three ways:

| Where | What is built | Over | CI |
| --- | --- | --- | --- |
| Natively | the whole package | libsodium | GHC 9.10.3, 9.12.4, 9.14.1 |
| WebAssembly, with the flag `wasm-libsodium` | the whole package | libsodium compiled for wasm32-wasi | `wasm32-wasi-ghc` 9.14.1 |
| WebAssembly without the flag, and the JavaScript backend | the client alone, `Crypto.OPAQUE.Client` | `@serenity-kit/opaque` | `wasm32-wasi-ghc` 9.14.1, `javascript-unknown-ghcjs-ghc` 9.12.2 |

`Crypto.OPAQUE.Client` is in all three, with the same names and types, so
an application's client code is written once.

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

With the cabal flag `wasm-libsodium` (off by default) the whole package
builds for wasm32-wasi over a libsodium compiled for it. Without the flag
the package is there [the client alone](#the-client-for-a-browser), so
that a program for the browser does not come to carry libsodium by
accident: read [the caveats](#memory) first.

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

A browser application rarely wants this: it needs the client only, and is
better served by an OPAQUE implementation built for the browser. The next
section is that, under this package's names.

### The client for a browser

On GHC's WebAssembly backend without the flag, and on its JavaScript
backend, the package is one module, `Crypto.OPAQUE.Client`: the client's
two steps of a registration and two steps of a login. They call
[`@serenity-kit/opaque`](https://github.com/serenity-kit/opaque) (opaque-ke
compiled to WebAssembly), which this package's server is tested against.
Natively the same module is this package's own client over libsodium, so
an application that builds for the browser and natively (for its tests,
say) imports `Crypto.OPAQUE.Client` in both and has no CPP.

The JavaScript is declared with
[haskell-halogen-jsbits](https://github.com/Swordlash/haskell-halogen/tree/master/jsbits),
which is not on Hackage: a project names its repository, as the two project
files here do.

```cabal
source-repository-package
  type: git
  location: https://github.com/Swordlash/haskell-halogen
  tag: 3459805e6476781961e2d754fe3574af0345ef09
  subdir: jsbits
```

For WebAssembly, with [ghc-wasm-meta](https://gitlab.haskell.org/haskell-wasm/ghc-wasm-meta)
(the project needs `shared: True`, for the Template Haskell splice that
embeds the JavaScript):

```sh
. ~/.ghc-wasm/env
cabal --project-file=cabal-wasm-client.project --builddir=dist-newstyle/wasm-client \
  --with-compiler="$(command -v wasm32-wasi-ghc-9.14.1.20260731)" \
  --with-hc-pkg="$(command -v wasm32-wasi-ghc-pkg-9.14.1.20260731)" build all
```

(The compiler is named on the command line, by its path, as well as in
the project file: with a native GHC on `PATH`, cabal may otherwise check
that GHC's `ghc-pkg` against the cross compiler and refuse, with "Version
mismatch between ghc and ghc-pkg". Where it refuses all the same, it has
kept the wrong `ghc-pkg` in the build directory: delete
`dist-newstyle/wasm-client/cache/compiler`, or `js-client`'s, and build
again.)

For the JavaScript backend, with ghcup's cross compiler, which is
installed and used under [emsdk](https://github.com/emscripten-core/emsdk)
(CI uses emsdk 3.1.74):

```sh
. ~/emsdk/emsdk_env.sh
ghcup config add-release-channel cross
emconfigure ghcup install ghc javascript-unknown-ghcjs-9.12.2
PATH="$(ghcup whereis basedir)/ghc/javascript-unknown-ghcjs-9.12.2/bin:$PATH"
cabal --project-file=cabal-js-client.project --builddir=dist-newstyle/js-client \
  --with-compiler="$(command -v javascript-unknown-ghcjs-ghc-9.12.2)" \
  --with-hc-pkg="$(command -v javascript-unknown-ghcjs-ghc-pkg-9.12.2)" build all
```

**Where the library comes from.** The client loads `@serenity-kit/opaque`
the first time a registration or a login starts, and waits for it:

1. from `globalThis.opaqueHsSerenity`, when the page or program set it: the
   module, a promise of it, or a function that returns either. A function
   is called only then, so a page can fetch the library, about half a
   megabyte, when a password is first used:

   ```js
   globalThis.opaqueHsSerenity = () => import("@serenity-kit/opaque");
   ```

   An application that bundles its JavaScript writes this line in a file
   its bundler reads.
2. otherwise from `import("@serenity-kit/opaque")` in the program's own
   JavaScript, which Node resolves from where that file is, and a browser
   only through an import map. The client's JavaScript does not write the
   name as a literal, so a bundler leaves this import alone.

Where neither gives the library, the step answers `ClientUnavailableError`
and the console says why.

**The export key in WebCrypto.** `Crypto.OPAQUE.Client.WebCrypto`, which
exists on these two backends only, has the two finishing steps again:
`finalizeRegistrationWebCrypto` and `clientFinishWebCrypto`. They give the
export key not as bytes but as a WebCrypto `CryptoKey`: the key material of
HKDF, not extractable, with the usages asked for (`DeriveKey`,
`DeriveBits`). The JavaScript hands the key serenity-kit returned straight
to `crypto.subtle.importKey`, so its bytes are never in the Haskell
program, and the application's own JavaScript derives its keys from the
`CryptoKey`:

```haskell
Right (ke3, sessionKey, held) <- clientFinishWebCrypto (DeriveKey :| []) config state ke2 defaultIdentities
-- held :: Maybe ExportCryptoKey, a newtype over the JavaScript object
```

Importing a key is asynchronous in WebCrypto, so both steps are in `IO`.
The key is `Nothing` where the page has no WebCrypto, which a browser
gives only to pages served over HTTPS and to localhost; the step has
still succeeded.

**What differs from the client over libsodium.** The module's haddock has
the list; in short:

- The `Config` must have the empty `context` and `Argon2id`: serenity-kit
  takes no context and has no `Identity`. Argon2id's memory is counted in
  KiB, `memLimit` rounded down, as libsodium rounds it, so both clients
  derive the same keys from the same `Config`.
- A password and an identity must be UTF-8. Anything else is
  `UnsupportedError`, as a context or `Identity` is.
- `clientFinish` answers `EnvelopeRecoveryError` for a wrong password, and
  also for a wrong MAC of the server's and a reflected OPRF value, which the
  client over libsodium tells apart.
- A state has no `Encoding`: it is a JavaScript object. Only the starting
  steps make one, so a state is proof that the library is loaded, and
  `clientFinish` is the pure function it is natively.
- `decode` checks a message's length only; an invalid group element fails
  the step that uses the message.
- Little can be zeroed: see [Memory](#memory).

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

**The client for a browser** is tested compiled, under Node, in two ways.
By itself, against serenity-kit's own server in the same process, which
needs only Node and `npm ci`:

```sh
sh scripts/client.sh wasm    # after the build for WebAssembly above; or: js
```

And driven by `opaque-test`, one command a line, against this package's
server and its client over libsodium: a registration by either client must
log in with the other to the same export key, with Argon2id's memory given
in bytes that are, and are not, a whole number of KiB. serenity-kit's
server never runs the key stretching, so only this test says that the two
clients read a `Config` alike.

```sh
OPAQUE_HS_CLIENT="sh scripts/client.sh wasm serve" cabal test opaque-test   # or: js
```

Both ways also run the steps that keep the export key in WebCrypto (Node
has it): the held key cannot be exported, and what HKDF derives from it is
what HKDF derives from the export key of this package's client over
libsodium, logged in to the same record.

Without `OPAQUE_HS_CLIENT` those tests are pending, and say so; with it, a
client that does not start fails them.

For wasm32-wasi with `wasm-libsodium` the test suite is one module, run under `wasmtime`
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

## Using it in your project

The package is not on Hackage yet. A project names this repository in its
`cabal.project`, pinned to one commit, and depends on `opaque-hs` in its
`.cabal` file:

```cabal
source-repository-package
  type: git
  location: https://github.com/Swordlash/opaque-hs
  tag: <a commit of this repository>
```

What else the project needs depends on where it builds:

- **Natively** (a server, or a client): libsodium 1.0.19 or later where
  `pkg-config` finds it, or the flag `older-libsodium`; see
  [Natively](#natively). A server that should run on machines without
  libsodium links the static library `scripts/libsodium.sh` builds.
- **In a browser** (a client): nothing of libsodium. The project also names
  haskell-halogen's repository for haskell-halogen-jsbits, and the page
  provides `@serenity-kit/opaque`; see
  [The client for a browser](#the-client-for-a-browser).
- **WebAssembly with the whole package**: the flag `wasm-libsodium` and the
  two directories of a libsodium compiled for wasm32-wasi; see
  [WebAssembly](#webassembly).

The package gives the protocol's steps and nothing around them. The
application decides how the messages travel (they are bytes: `encode` and
`decode`), where the server keeps its `ServerSetup` and the records, which
Argon2id parameters a record was made with (the server must tell the client
at each login, so it stores them beside the record), how long a login under
way is kept between KE2 and KE3, and what the session key and the export
key are used for.

**An application that uses it** is the wiki this package was written for,
[Swordlash/wiki](https://github.com/Swordlash/wiki), where a password signs
in through OPAQUE:

- [`cabal.project`](https://github.com/Swordlash/wiki/blob/main/cabal.project)
  pins this repository, and
  [`toolchain/libsodium.sh`](https://github.com/Swordlash/wiki/blob/main/toolchain/libsodium.sh)
  builds the libsodium its server is linked with statically.
- [`Wiki.Server.Opaque`](https://github.com/Swordlash/wiki/blob/main/wiki-server/src/Wiki/Server/Opaque.hs)
  is the server's side: the `ServerSetup` made once and kept in the
  database, Argon2id's parameters stored beside each record and sent with
  every challenge, the logins under way kept for two minutes, and the fake
  record for a login nobody has.
- [`Wiki.Api.Opaque`](https://github.com/Swordlash/wiki/blob/main/wiki-api/src/Wiki/Api/Opaque.hs)
  is the messages as its HTTP API carries them, in base64url.
- [`Wiki.App.Backend.Opaque`](https://github.com/Swordlash/wiki/blob/main/wiki-app/src/Wiki/App/Backend/Opaque.hs)
  is the client: this package's natively, where the server's tests sign in
  through it, and `@serenity-kit/opaque` in the browser, through a binding
  of the wiki's own that is older than `Crypto.OPAQUE.Client`. There the
  export key becomes a WebCrypto key that wraps the user's own keys.

### An example: a servant server and its client

[`examples/servant/Main.hs`](examples/servant/Main.hs) is one program with
both sides. It starts a small HTTP server, written with servant, that
keeps everything in memory, runs a client against it while the server is
up, and prints what each request came to:

```sh
cabal --project-file=cabal-examples.project run opaque-hs-servant-example
```

```
register ada: registered
register ada again: refused by the server: HTTP 409
log in as ada with a wrong password: refused by the client: EnvelopeRecoveryError
log in as grace, whom the server does not know: refused by the client: EnvelopeRecoveryError
log in as ada: logged in, with a token
GET /me with the token: Ada Lovelace, born 1815-12-10
GET /me without a token: refused by the server: HTTP 401
```

A registration is two requests and a login is two, one round trip of
OPAQUE's messages each; the user's first name, last name and date of birth
go with the registration's second request. A login ends with a token, and
`GET /me` gives the registered details back to whoever sends it. The server
answers a login for a name it does not know with the fake record, so the
client fails there exactly as with a wrong password. The comments say what
a real application adds: TLS, a database, a time limit on a login under
way.

### The steps

A program that is only ever a client imports `Crypto.OPAQUE.Client`, on
every backend. The server, and a program that is both, imports
`Crypto.OPAQUE`:

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

With the client for a browser on the other side, `context` is `""`:
serenity-kit takes none.
