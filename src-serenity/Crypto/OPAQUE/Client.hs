-- | The client's half of OPAQUE (RFC 9807), on every backend: the two steps
-- of a registration and the two steps of a login, with the same names and
-- types wherever the package is built. A program that only ever is a
-- client, such as a browser application, imports this module and no other.
--
-- This is the module as GHC's WebAssembly backend (without the flag
-- @wasm-libsodium@) and its JavaScript backend build it. There the steps
-- are not this package's own protocol code, which needs libsodium: they
-- call @\@serenity-kit\/opaque@, opaque-ke compiled to WebAssembly, the
-- library a browser would use anyway. Natively the same module is the
-- client of "Crypto.OPAQUE", over libsodium, and the package's tests run
-- one against the other.
--
-- > (state, request) <- registrationRequest password              -- an Either, as below
-- > -- send the request; the server answers with a response
-- > (record, exportKey) <- finalizeRegistration config state response defaultIdentities
-- > -- send the record
--
-- > (state, ke1) <- clientStart password
-- > -- send KE1; the server answers with KE2
-- > (ke3, sessionKey, exportKey) = clientFinish config state ke2 defaultIdentities
-- > -- send KE3
--
-- = Where the library comes from
--
-- The first 'registrationRequest' or 'clientStart' loads
-- @\@serenity-kit\/opaque@ and waits for it. It takes the library from
-- @globalThis.opaqueHsSerenity@ when the page or program set that (the
-- module, a promise of it, or a function that returns either, called only
-- then, so that a page can fetch the library when a password is first
-- used), and otherwise from @import("\@serenity-kit\/opaque")@, which Node
-- resolves and a browser resolves only through an import map. An
-- application that bundles its JavaScript sets the global. Where the
-- library cannot be loaded, the step gives 'ClientUnavailableError', and
-- the next step tries again.
--
-- Waiting for the library means waiting for a JavaScript promise, so on
-- WebAssembly the two starting steps must run where a thread may wait:
-- under an asynchronous export, as a Halogen application's handlers do.
--
-- A t'ClientRegState' or a t'ClientLoginState' is made only by those two
-- steps and has no 'Encoding' here. So whoever holds one has proof that the
-- library is loaded, which is why 'clientFinish' can be the pure function
-- it is natively: it calls a library that is there, and waits for nothing.
--
-- = What differs from the client over libsodium
--
-- * A t'Config' must have the empty context and 'Argon2id': serenity-kit
--   takes no context and has no 'Identity' stretching. Argon2id runs with
--   parallelism 1, and its memory is counted in KiB, @memLimit@ rounded
--   down, as libsodium rounds it.
-- * A password and an identity must be UTF-8: serenity-kit takes them as
--   JavaScript strings, and hashes their UTF-8 bytes.
-- * The steps give 'UnsupportedError' for those two, and tell fewer
--   failures apart: 'clientFinish' gives 'EnvelopeRecoveryError' for a
--   wrong password, and also where the client over libsodium gives
--   'ServerAuthenticationError' or 'ReflectedValueError'.
-- * 'decode' checks a message's length only. A message with an invalid
--   group element fails the step that uses it, with 'DeserializeError'.
-- * Nothing is locked in memory, and little can be zeroed. The states hold
--   the password and serenity-kit's own state as JavaScript strings, which
--   are immutable: 'scrub' drops them, and the engine frees them when it
--   will. A t'SessionKey' and an t'ExportKey' are bytes in the program's
--   heap, which 'scrub' zeroes; the strings serenity-kit returned them in,
--   and the text this module decoded them from, cannot be. In a browser any
--   script on the page can read all of it.
--   "Crypto.OPAQUE.Client.WebCrypto" has the two finishing steps with the
--   export key kept in the browser's WebCrypto instead, where its bytes
--   never reach the program.
module Crypto.OPAQUE.Client
  ( -- * Configuration
    Config (..)
  , Ksf (..)
  , Identities (..)
  , defaultIdentities
  , Error (..)

    -- * Registration
  , RegistrationRequest
  , RegistrationResponse
  , RegistrationRecord
  , ClientRegState
  , registrationRequest
  , finalizeRegistration

    -- * Login
  , KE1
  , KE2
  , KE3
  , ClientLoginState
  , SessionKey
  , ExportKey
  , clientStart
  , clientFinish

    -- * Encodings
  , Encoding (..)

    -- * Memory
  , Scrub (..)
  )
where

import Crypto.OPAQUE.Client.Serenity
import Crypto.OPAQUE.Types
