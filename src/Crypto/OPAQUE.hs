-- | OPAQUE, the augmented password-authenticated key exchange of RFC 9807,
-- with the suite ristretto255, SHA-512 and the 3DH key exchange.
--
-- OPAQUE lets a client prove that it knows a password to a server that
-- never sees the password, not even at registration. The server keeps a
-- 'RegistrationRecord' per client; a thief of the records cannot test a
-- password guess against them without the server's 'ServerSetup', and even
-- with it must pay for every guess with the key stretching function. A
-- login also agrees on a 'SessionKey', and gives the client an 'ExportKey'
-- that only the client can compute.
--
-- Registration takes one round trip and an upload:
--
-- > (clientState, request) <- registrationRequest password    -- client
-- > response = registrationResponse setup credentialId request -- server
-- > (record, exportKey) <- finalizeRegistration config clientState response ids -- client
-- > -- the client sends the record; the server stores it under credentialId
--
-- A login takes three messages:
--
-- > (clientState, ke1) <- clientStart password                                  -- client
-- > (serverState, ke2) <- serverRespond config setup (Just record) credentialId ke1 ids -- server
-- > (ke3, sessionKey, exportKey) = clientFinish config clientState ke2 ids         -- client
-- > sessionKey' = serverFinish serverState ke3                                   -- server
--
-- A server answers a login for a client it has no record of with
-- @serverRespond … Nothing …@, which answers with a fake record, so that the
-- answer does not tell whether the client exists; the client then fails at
-- 'clientFinish' as with a wrong password.
--
-- Every message, record and state is turned to bytes and back with
-- 'Encoding'. Messages are encoded byte for byte as the RFC's structures.
--
-- The states, the setup and the keys keep their secrets in memory the
-- package zeroes when the values are freed ("Crypto.OPAQUE.Secret"); a
-- caller that knows a value's lifetime has ended zeroes it at once with
-- 'scrub'. The encoding of a value that holds secrets is a copy the caller
-- must protect.
module Crypto.OPAQUE
  ( -- * Configuration
    Config (..)
  , Ksf (..)
  , Identities (..)
  , defaultIdentities
  , CredentialId (..)
  , Error (..)

    -- * Server setup
  , ServerSetup
  , generateServerSetup

    -- * Registration
  , RegistrationRequest
  , RegistrationResponse
  , RegistrationRecord
  , ClientRegState
  , registrationRequest
  , registrationResponse
  , finalizeRegistration

    -- * Login
  , KE1
  , KE2
  , KE3
  , ClientLoginState
  , ServerLoginState
  , SessionKey
  , ExportKey
  , clientStart
  , serverRespond
  , clientFinish
  , serverFinish

    -- * Encodings
  , Encoding (..)

    -- * Memory
  , Scrub (..)
  )
where

import Crypto.OPAQUE.Internal
