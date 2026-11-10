-- | The client's half of OPAQUE (RFC 9807), on every backend: the two steps
-- of a registration and the two steps of a login, with the same names and
-- types wherever the package is built. A program that only ever is a
-- client, such as a browser application that also builds natively for its
-- tests, imports this module and no other, and its code is the same
-- everywhere.
--
-- This is the module as it is built natively, and for GHC's WebAssembly
-- backend with the flag @wasm-libsodium@: the client of "Crypto.OPAQUE",
-- this package's own protocol code over libsodium, and nothing but a list
-- of what a client needs from it. Without that flag on WebAssembly, and on
-- GHC's JavaScript backend, libsodium is not there, and the same names
-- call @\@serenity-kit\/opaque@ (opaque-ke compiled to WebAssembly)
-- instead; the package's tests run the two against each other.
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
-- Code meant for every backend keeps to what both clients do:
--
-- * A t'Config' with the empty context and 'Argon2id' (serenity-kit takes
--   no context and has no 'Identity' stretching), and a password and
--   identities that are UTF-8. The other client gives 'UnsupportedError'
--   for anything else.
-- * No encoding of a t'ClientRegState' or a t'ClientLoginState': the other
--   client has none.
-- * One failure of 'clientFinish' for a wrong password, a server whose MAC
--   is wrong and a reflected OPRF value: this client tells them apart
--   ('EnvelopeRecoveryError', 'ServerAuthenticationError',
--   'ReflectedValueError'), the other gives 'EnvelopeRecoveryError' for
--   all three.
--
-- This client keeps its secrets in memory libsodium zeroes
-- ("Crypto.OPAQUE.Secret"); the other cannot. The other has a module more,
-- @Crypto.OPAQUE.Client.WebCrypto@, not built here, whose finishing steps
-- keep the export key in the browser's WebCrypto.
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

import Crypto.OPAQUE.Internal
