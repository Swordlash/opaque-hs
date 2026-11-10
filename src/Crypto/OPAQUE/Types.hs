-- | The types every backend of the package shares: the configuration, the
-- identities, the errors, and the two classes of its values, 'Encoding' and
-- 'Scrub'.
--
-- The package has two implementations of the protocol. Natively (and for
-- WebAssembly with the flag @wasm-libsodium@) it is "Crypto.OPAQUE", written
-- over libsodium. For GHC's WebAssembly and JavaScript backends it is the
-- client alone, "Crypto.OPAQUE.Client", which calls @\@serenity-kit\/opaque@.
-- Both speak in these types, so that an application's code is the same on
-- every backend. Nothing here needs libsodium or JavaScript.
module Crypto.OPAQUE.Types
  ( -- * Configuration
    Config (..)
  , Ksf (..)
  , Identities (..)
  , defaultIdentities
  , CredentialId (..)
  , Error (..)

    -- * Classes
  , Encoding (..)
  , Scrub (..)
  )
where

import Data.ByteString (ByteString)
import Data.Word (Word64)

-- | t'Config' is what both parties must agree on beyond the suite.
--
-- @context@ is the RFC's shared context string, mixed into every key the
-- exchange derives, so that a transcript of one application is useless in
-- another (the RFC's test vectors use @"OPAQUE-POC"@). @ksf@ is the key
-- stretching function the client applies to the OPRF's output: the server
-- never runs it, but must tell the client which one a record was made with.
data Config = Config
  { context :: ByteString
  , ksf :: Ksf
  }
  deriving stock (Eq, Show)

-- | 'Ksf' is the key stretching function: a slow hash that makes each guess
-- of a password expensive for someone who has stolen the server's records.
data Ksf
  = -- | No stretching: the output is the input. The RFC's test vectors use
    -- it so that they can be reproduced quickly. Never use it for real
    -- passwords.
    Identity
  | -- | Argon2id version 1.3 (RFC 9106) with parallelism 1, a salt of 16 zero
    -- bytes (the RFC's choice: the OPRF's output is already unique to the
    -- user and the server), the given number of passes and the given memory
    -- in bytes, and a 64-byte output.
    Argon2id
      { opsLimit :: Word64
      , memLimit :: Word64
      }
  deriving stock (Eq, Show)

-- | t'Identities' are the optional identities of the client and the server.
-- An identity left out stands for the party's public key, which is the
-- RFC's default and what 'defaultIdentities' gives. Both parties must use
-- the same identities at registration and at every login.
data Identities = Identities
  { client :: Maybe ByteString
  , server :: Maybe ByteString
  }
  deriving stock (Eq, Show)

-- | No identities: both stand for the parties' public keys.
defaultIdentities :: Identities
defaultIdentities = Identities {client = Nothing, server = Nothing}

-- | t'CredentialId' is the server's name for one client's record: the RFC's
-- @credential_identifier@. The server derives the client's OPRF key from it,
-- so it must never change for a record, and two records must never share
-- one.
newtype CredentialId = CredentialId ByteString
  deriving stock (Eq, Show)

-- | 'Error' is every way a step can fail, with the RFC's names, and two
-- more that only the client of the WebAssembly and JavaScript backends
-- gives. That client, which asks @\@serenity-kit\/opaque@, also tells fewer
-- failures apart: "Crypto.OPAQUE.Client" says which.
data Error
  = -- | A message's bytes have the wrong length or hold an invalid group
    -- element.
    DeserializeError
  | -- | The password is 65535 bytes or more (RFC 9497, section 5.1), an
    -- identity or the context is longer than its two-byte length can say
    -- (65536 bytes or more), a random value given
    -- has the wrong length, a blind is zero, or the password hashes to the
    -- group's identity (negligible probability).
    InvalidInputError
  | -- | The server's evaluated element is the client's own blinded element
    -- sent back: a server that reflects the OPRF instead of evaluating it.
    -- RFC 9807 does not require the check; opaque-ke makes it, and so does
    -- this package.
    ReflectedValueError
  | -- | A key pair could not be derived from a seed (negligible probability).
    DeriveKeyPairError
  | -- | The key stretching function failed: Argon2id's limits are out of
    -- range, or its memory could not be allocated.
    KsfError
  | -- | The client could not open its envelope: the password is wrong, or
    -- the server answered for a record that does not exist.
    EnvelopeRecoveryError
  | -- | The server's MAC in KE2 is wrong.
    ServerAuthenticationError
  | -- | The client's MAC in KE3 is wrong.
    ClientAuthenticationError
  | -- | The client of the WebAssembly and JavaScript backends
    -- ("Crypto.OPAQUE.Client") cannot do what was asked, although the
    -- protocol allows it: a context other than the empty one, the
    -- 'Identity' stretching, or a password or an identity that is not
    -- UTF-8. @\@serenity-kit\/opaque@ takes no context and takes the three
    -- others as JavaScript strings. Never given by the client over
    -- libsodium.
    UnsupportedError
  | -- | The client of the WebAssembly and JavaScript backends could not load
    -- @\@serenity-kit\/opaque@: the page or program does not provide it.
    -- The browser's console has the reason. Never given by the client over
    -- libsodium.
    ClientUnavailableError
  deriving stock (Eq, Show)

-- | 'Encoding' turns a value to bytes and back. Messages and records are
-- encoded exactly as the RFC's structures (fixed-length fields one after
-- another). States, which the RFC never sends, are encoded the same way;
-- a client state ends with the password. 'decode' checks lengths and that
-- every group element is valid. (The client of the WebAssembly and
-- JavaScript backends has no group arithmetic of its own: its 'decode'
-- checks lengths only, and an invalid element fails the step that uses the
-- message.)
class Encoding a where
  encode :: a -> ByteString
  decode :: ByteString -> Either Error a

-- | 'Scrub' zeroes a value's secrets now, for a caller that knows the
-- value's lifetime has ended: a login state once the login has finished, a
-- session key once it has been used. The value must not be used afterwards.
-- Without it, the secrets are zeroed when the garbage collector frees them.
-- (Over libsodium. "Crypto.OPAQUE.Client" says what the client of the
-- WebAssembly and JavaScript backends can and cannot zero.)
class Scrub a where
  scrub :: a -> IO ()
