{-# LANGUAGE TemplateHaskell #-}

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

import Crypto.OPAQUE.Types
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Functor ((<&>))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeLatin1, decodeUtf8', encodeUtf8)
import Foreign.Marshal.Utils (fillBytes)
import Halogen.JSBits (JSText, JSVal, Safety (..), browserJS, fromJSText, toJSText)
import Halogen.JSBits.Promise (Promise, waitCatch)
import System.IO.Unsafe (unsafePerformIO)
import Text.Read (readMaybe)

-- The password and the identities cross as strings, and the messages and
-- keys as strings of unpadded base64url, which is how serenity-kit takes
-- and gives them. An identity is a flag and a string, since an empty
-- identity is not the same as none.
$( browserJS
     ["jsbits/opaque.js"]
     [ ("js_start", "opaque_hs_start", Safe, [t|Bool -> JSText -> IO (Promise JSVal)|])
     , ("js_status", "opaque_hs_status", Unsafe, [t|JSVal -> IO Int|])
     , ("js_message", "opaque_hs_message", Unsafe, [t|JSVal -> IO JSText|])
     , ("js_forget", "opaque_hs_forget", Unsafe, [t|JSVal -> IO ()|])
     , ("js_finish_login", "opaque_hs_finish_login", Safe, [t|JSVal -> JSText -> Double -> Double -> Bool -> JSText -> Bool -> JSText -> IO JSText|])
     , ("js_finish_registration", "opaque_hs_finish_registration", Safe, [t|JSVal -> JSText -> Double -> Double -> Bool -> JSText -> Bool -> JSText -> IO JSText|])
     ]
 )

-- Fixed sizes of the suite: an element or a scalar, a nonce, and a hash or
-- a MAC.
elementBytes, nonceBytes, hashBytes :: Int
elementBytes = 32
nonceBytes = 32
hashBytes = 64

-- | Bytes of exactly this length, as 'decode' accepts a message here.
sized :: Int -> ByteString -> Either Error ByteString
sized n bs = if BS.length bs == n then Right bs else Left DeserializeError

-- | t'RegistrationRequest' is the client's first registration message: the
-- password, blinded by the OPRF.
newtype RegistrationRequest = RegistrationRequest ByteString
  deriving stock (Eq, Show)

instance Encoding RegistrationRequest where
  encode (RegistrationRequest b) = b
  decode = fmap RegistrationRequest . sized elementBytes

-- | t'RegistrationResponse' is the server's answer to a registration
-- request: the OPRF evaluated under the client's key, and the server's
-- public key.
newtype RegistrationResponse = RegistrationResponse ByteString
  deriving stock (Eq, Show)

instance Encoding RegistrationResponse where
  encode (RegistrationResponse b) = b
  decode = fmap RegistrationResponse . sized (2 * elementBytes)

-- | The length of a record: a public key, a masking key, and an envelope (a
-- nonce and a MAC).
recordBytes :: Int
recordBytes = elementBytes + hashBytes + nonceBytes + hashBytes

-- | t'RegistrationRecord' is what the server keeps for a client: the
-- client's public key, the key that masks a login's answer, and the
-- envelope.
newtype RegistrationRecord = RegistrationRecord ByteString
  deriving stock (Eq, Show)

instance Encoding RegistrationRecord where
  encode (RegistrationRecord b) = b
  decode = fmap RegistrationRecord . sized recordBytes

-- | The length of KE1: the blinded password, a nonce and the client's
-- ephemeral public key.
ke1Bytes :: Int
ke1Bytes = 2 * elementBytes + nonceBytes

-- | t'KE1' is the client's first login message.
newtype KE1 = KE1 ByteString
  deriving stock (Eq, Show)

instance Encoding KE1 where
  encode (KE1 b) = b
  decode = fmap KE1 . sized ke1Bytes

-- | The length of KE2: the credential response (an element, a nonce, and
-- the masked public key and envelope), a nonce, the server's ephemeral
-- public key and its MAC.
ke2Bytes :: Int
ke2Bytes = credentialResponse + nonceBytes + elementBytes + hashBytes
  where
    credentialResponse = elementBytes + nonceBytes + masked
    masked = elementBytes + nonceBytes + hashBytes

-- | t'KE2' is the server's login message.
newtype KE2 = KE2 ByteString
  deriving stock (Eq, Show)

instance Encoding KE2 where
  encode (KE2 b) = b
  decode = fmap KE2 . sized ke2Bytes

-- | t'KE3' is the client's last login message: a MAC that proves the client
-- knew the password.
newtype KE3 = KE3 ByteString
  deriving stock (Eq, Show)

instance Encoding KE3 where
  encode (KE3 b) = b
  decode = fmap KE3 . sized hashBytes

-- | t'ClientRegState' is what the client keeps between its registration
-- request and the server's response: a JavaScript object holding
-- serenity-kit's state and the password. Only 'registrationRequest' makes
-- one.
newtype ClientRegState = ClientRegState JSVal

-- | t'ClientLoginState' is what the client keeps between KE1 and KE2: a
-- JavaScript object holding serenity-kit's state and the password. Only
-- 'clientStart' makes one.
newtype ClientLoginState = ClientLoginState JSVal

-- | t'SessionKey' is the secret the two parties agree on at login, 64
-- bytes. Each login has a different one.
newtype SessionKey = SessionKey ByteString

-- | The encoding is the key: a copy the caller must protect.
instance Encoding SessionKey where
  encode (SessionKey k) = BS.copy k
  decode = fmap (SessionKey . BS.copy) . sized hashBytes

-- | t'ExportKey' is a secret, 64 bytes, that only the client can compute,
-- the same at registration and at every login with the same record. The
-- server never learns it. 'clientFinish' gives it only once the server is
-- authenticated.
newtype ExportKey = ExportKey ByteString

-- | The encoding is the key: a copy the caller must protect.
instance Encoding ExportKey where
  encode (ExportKey k) = BS.copy k
  decode = fmap (ExportKey . BS.copy) . sized hashBytes

-- | Drops the password and serenity-kit's state, which cannot be zeroed. A
-- step given the state afterwards fails with 'InvalidInputError'.
instance Scrub ClientRegState where scrub (ClientRegState o) = js_forget o

-- | Drops the password and serenity-kit's state, which cannot be zeroed. A
-- step given the state afterwards fails with 'InvalidInputError'.
instance Scrub ClientLoginState where scrub (ClientLoginState o) = js_forget o

-- | Zeroes the key's bytes.
instance Scrub SessionKey where scrub (SessionKey k) = wipe k

-- | Zeroes the key's bytes.
instance Scrub ExportKey where scrub (ExportKey k) = wipe k

-- | Zero a 'ByteString' in place. Only for bytes this module made and gave
-- to nobody else: a key's own buffer.
wipe :: ByteString -> IO ()
wipe bs = unsafeUseAsCStringLen bs (\(p, n) -> fillBytes p 0 n)

-- | A status of @jsbits\/opaque.js@ as an error.
errorOf :: Int -> Error
errorOf = \case
  2 -> InvalidInputError
  3 -> ReflectedValueError
  4 -> KsfError
  5 -> EnvelopeRecoveryError
  _ -> DeserializeError

-- | Bytes as serenity-kit carries a message or a key: unpadded base64url.
base64 :: ByteString -> JSText
base64 = toJSText . decodeLatin1 . Base64.encodeUnpadded

-- | The bytes of a word serenity-kit gave, when they have this length.
unbase64 :: Int -> Text -> Either Error ByteString
unbase64 size = either (const (Left DeserializeError)) (sized size) . Base64.decodeUnpadded . encodeUtf8

-- | The text UTF-8 bytes spell, for serenity-kit, which takes a password
-- and an identity as a JavaScript string and hashes its UTF-8 bytes. Bytes
-- that are not UTF-8 have no such string. A byte order mark stays, as any
-- other character.
utf8 :: ByteString -> Either Error Text
utf8 = either (const (Left UnsupportedError)) Right . decodeUtf8'

-- | Start a login or a registration: the state, and the message of the
-- given length.
start :: Bool -> Int -> ByteString -> IO (Either Error (JSVal, ByteString))
start login size password
  -- RFC 9497, section 5.1: the OPRF's input is shorter than 2^16 - 1 bytes.
  | BS.length password >= 65535 = pure (Left InvalidInputError)
  | otherwise = case utf8 password of
      Left e -> pure (Left e)
      Right text ->
        (waitCatch =<< js_start login (toJSText text)) >>= \case
          Left _ -> pure (Left ClientUnavailableError)
          Right started ->
            js_status started >>= \case
              0 -> fmap (started,) . unbase64 size . fromJSText <$> js_message started
              status -> pure (Left (errorOf status))

-- | The registration's first step, the RFC's CreateRegistrationRequest:
-- blind the password. It gives the state to keep and the request to send.
-- The password is its UTF-8 bytes. The first call loads
-- @\@serenity-kit\/opaque@ and waits for it.
registrationRequest :: ByteString -> IO (Either Error (ClientRegState, RegistrationRequest))
registrationRequest password =
  fmap (\(state, message) -> (ClientRegState state, RegistrationRequest message)) <$> start False elementBytes password

-- | The login's first step, the RFC's GenerateKE1: blind the password and
-- make an ephemeral key pair. It gives the state to keep and KE1 to send.
-- The password is its UTF-8 bytes. The first call loads
-- @\@serenity-kit\/opaque@ and waits for it.
clientStart :: ByteString -> IO (Either Error (ClientLoginState, KE1))
clientStart password =
  fmap (\(state, message) -> (ClientLoginState state, KE1 message)) <$> start True ke1Bytes password

-- | Argon2id's passes and its memory in KiB, as serenity-kit takes them
-- (two 32-bit numbers), from a configuration this client can follow.
-- libsodium takes @memLimit@ in bytes and divides it by 1024 the same way,
-- and has the same least values: one pass and 8 KiB.
stretching :: Config -> Either Error (Double, Double)
stretching config
  | not (BS.null config.context) = Left UnsupportedError
  | otherwise = case config.ksf of
      Identity -> Left UnsupportedError
      Argon2id {opsLimit, memLimit}
        | opsLimit < 1 || opsLimit > most || kib < 8 || kib > most -> Left KsfError
        | otherwise -> Right (fromIntegral opsLimit, fromIntegral kib)
        where
          kib = memLimit `div` 1024
          most = 4294967295

-- | A finishing step: the words of its results, each in base64url.
finish
  :: (JSVal -> JSText -> Double -> Double -> Bool -> JSText -> Bool -> JSText -> IO JSText)
  -> Config
  -> JSVal
  -> ByteString
  -> Identities
  -> IO (Either Error [Text])
finish step config state message ids = case (,,) <$> stretching config <*> identity ids.client <*> identity ids.server of
  Left e -> pure (Left e)
  Right ((passes, kib), (hasClient, client), (hasServer, server)) -> do
    answer <- fromJSText <$> step state (base64 message) passes kib hasClient client hasServer server
    pure $ case T.words answer of
      "ok" : results -> Right results
      ["fail", status] -> Left (maybe DeserializeError errorOf (readMaybe (T.unpack status)))
      _ -> Left DeserializeError
  where
    -- Whether there is an identity, and its text. Its length is written in
    -- two bytes.
    identity = \case
      Nothing -> Right (False, toJSText T.empty)
      Just bytes
        | BS.length bytes >= 65536 -> Left InvalidInputError
        | otherwise -> (True,) . toJSText <$> utf8 bytes

-- | The registration's last step, the RFC's FinalizeRegistrationRequest:
-- with the server's response, stretch the OPRF's output and make the
-- record to send, which the server stores. It also gives the export key.
finalizeRegistration :: Config -> ClientRegState -> RegistrationResponse -> Identities -> IO (Either Error (RegistrationRecord, ExportKey))
finalizeRegistration config (ClientRegState state) (RegistrationResponse response) ids =
  finish js_finish_registration config state response ids <&> \case
    Right [record, exportKey] -> (,) <$> (RegistrationRecord <$> unbase64 recordBytes record) <*> (ExportKey <$> unbase64 hashBytes exportKey)
    Right _ -> Left DeserializeError
    Left e -> Left e

-- | The login's last step, the RFC's GenerateKE3: with the server's KE2,
-- recover the client's key from the envelope, check the server's MAC, and
-- give KE3 to send, the session key and the export key. It fails with
-- 'EnvelopeRecoveryError' for a wrong password, for a client the server has
-- no record of, and for a server that is not the one the record was made
-- with.
--
-- It is a pure function, as it is over libsodium: the state says that the
-- library is loaded, so the call waits for nothing, and the same arguments
-- give the same result.
clientFinish :: Config -> ClientLoginState -> KE2 -> Identities -> Either Error (KE3, SessionKey, ExportKey)
clientFinish config (ClientLoginState state) (KE2 ke2) ids =
  unsafePerformIO $
    finish js_finish_login config state ke2 ids <&> \case
      Right [ke3, sessionKey, exportKey] ->
        (,,) <$> (KE3 <$> unbase64 hashBytes ke3) <*> (SessionKey <$> unbase64 hashBytes sessionKey) <*> (ExportKey <$> unbase64 hashBytes exportKey)
      Right _ -> Left DeserializeError
      Left e -> Left e
