-- | The client's two finishing steps with the export key kept in the
-- browser's WebCrypto: the steps of "Crypto.OPAQUE.Client" give an
-- t'ExportKey', bytes in the program's memory, and these give a WebCrypto
-- @CryptoKey@ that holds the same key and cannot be exported.
--
-- This module exists only where "Crypto.OPAQUE.Client" calls
-- @\@serenity-kit\/opaque@: on GHC's WebAssembly backend without the flag
-- @wasm-libsodium@, and on its JavaScript backend. There is no WebCrypto
-- natively.
--
-- The export key is the one secret of a login that an application keeps
-- using: it derives from it the keys that encrypt the user's data. In a
-- browser the place for such a key is WebCrypto, which can use a key
-- without ever giving its bytes back to the page. So here the JavaScript
-- hands the key that serenity-kit returned straight to
-- @crypto.subtle.importKey@, as the key material of HKDF, not extractable,
-- and the program gets the @CryptoKey@. The key's bytes are never in the
-- Haskell program, neither as an t'ExportKey' nor on the way to one. (The
-- JavaScript string serenity-kit returned the key in exists until the
-- engine frees it, here as with the other steps.)
--
-- > Right (ke3, sessionKey, held) <- clientFinishWebCrypto (DeriveKey :| []) config state ke2 defaultIdentities
-- > for_ held $ \(ExportCryptoKey key) -> deriveMyKeys key   -- the application's own JavaScript
--
-- An application derives its keys from the @CryptoKey@ with
-- @crypto.subtle.deriveKey@ or @deriveBits@, HKDF with the hash, salt and
-- info it chooses.
--
-- A page served over plain HTTP has no WebCrypto: a browser gives
-- @crypto.subtle@ only to pages served over HTTPS and to localhost. The
-- client does not need it, and a registration or a login works there as
-- anywhere. These two steps then succeed and give 'Nothing' for the key.
--
-- Importing a key is asynchronous in WebCrypto, so both steps wait for a
-- JavaScript promise, and 'clientFinishWebCrypto' is in 'IO', unlike
-- 'Crypto.OPAQUE.Client.clientFinish'. On WebAssembly they must run where a
-- thread may wait, as the two starting steps must.
module Crypto.OPAQUE.Client.WebCrypto
  ( ExportCryptoKey (..)
  , KeyUsage (..)
  , finalizeRegistrationWebCrypto
  , clientFinishWebCrypto
  )
where

import Crypto.OPAQUE.Client.Serenity
import Crypto.OPAQUE.Types
import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NonEmpty
import Data.Text (Text)
import Data.Text qualified as T
import Halogen.JSBits (JSText, JSVal, fromJSText, isNull, toJSText)
import Halogen.JSBits.Promise (Promise, waitCatch)

-- | t'ExportCryptoKey' is the export key as a WebCrypto @CryptoKey@: the
-- key material of HKDF (its algorithm is @HKDF@), not extractable. The
-- value is the JavaScript object, for the application's own JavaScript to
-- derive keys from.
newtype ExportCryptoKey = ExportCryptoKey JSVal

-- | 'KeyUsage' is what WebCrypto lets the key be used for.
data KeyUsage
  = -- | @crypto.subtle.deriveKey@: derive another @CryptoKey@ from it.
    DeriveKey
  | -- | @crypto.subtle.deriveBits@: derive bytes from it, which the page
    -- can read.
    DeriveBits
  deriving stock (Eq, Show)

-- | The usages as @importKey@ takes them, with a space between.
usagesText :: NonEmpty KeyUsage -> JSText
usagesText = toJSText . T.unwords . map name . NonEmpty.toList
  where
    name = \case
      DeriveKey -> "deriveKey"
      DeriveBits -> "deriveBits"

-- | A finishing step whose export key stays in WebCrypto: the words of its
-- other results, each in base64url, and the key, if there is WebCrypto.
finishHeld
  :: (JSVal -> JSText -> Double -> Double -> Bool -> JSText -> Bool -> JSText -> JSText -> IO (Promise JSVal))
  -> NonEmpty KeyUsage
  -> Config
  -> JSVal
  -> ByteString
  -> Identities
  -> IO (Either Error ([Text], Maybe ExportCryptoKey))
finishHeld step usages config state message ids = case given config ids of
  Left e -> pure (Left e)
  Right g ->
    (waitCatch =<< step state (base64 message) g.passes g.kib g.hasClient g.client g.hasServer g.server (usagesText usages)) >>= \case
      -- The JavaScript settles its promise with an answer in every case.
      Left _ -> pure (Left DeserializeError)
      Right held -> do
        answer <- fromJSText <$> js_held_answer held
        key <- js_held_key held
        pure ((,if isNull key then Nothing else Just (ExportCryptoKey key)) <$> answered answer)

-- | The registration's last step, as
-- 'Crypto.OPAQUE.Client.finalizeRegistration', with the export key held in
-- WebCrypto: the record to send, and the key with the given usages.
--
-- The key is 'Nothing' where the page has no WebCrypto (a browser gives it
-- only to pages served over HTTPS and to localhost) or WebCrypto refuses
-- the key. The step has still succeeded and the record is good; the
-- export key is then not given in any other form.
finalizeRegistrationWebCrypto
  :: NonEmpty KeyUsage
  -> Config
  -> ClientRegState
  -> RegistrationResponse
  -> Identities
  -> IO (Either Error (RegistrationRecord, Maybe ExportCryptoKey))
finalizeRegistrationWebCrypto usages config (ClientRegState state) (RegistrationResponse response) ids =
  finishHeld js_finish_registration_held usages config state response ids >>= \case
    Right ([record], key) -> pure ((,key) . RegistrationRecord <$> unbase64 recordBytes record)
    Right _ -> pure (Left DeserializeError)
    Left e -> pure (Left e)

-- | The login's last step, as 'Crypto.OPAQUE.Client.clientFinish', with
-- the export key held in WebCrypto: KE3 to send, the session key, and the
-- export key with the given usages. It fails as 'clientFinish' does.
--
-- The key is 'Nothing' where the page has no WebCrypto (a browser gives it
-- only to pages served over HTTPS and to localhost) or WebCrypto refuses
-- the key. The login has still succeeded; the export key is then not given
-- in any other form.
clientFinishWebCrypto
  :: NonEmpty KeyUsage
  -> Config
  -> ClientLoginState
  -> KE2
  -> Identities
  -> IO (Either Error (KE3, SessionKey, Maybe ExportCryptoKey))
clientFinishWebCrypto usages config (ClientLoginState state) (KE2 ke2) ids =
  finishHeld js_finish_login_held usages config state ke2 ids >>= \case
    Right ([ke3, sessionKey], key) ->
      pure ((,,key) <$> (KE3 <$> unbase64 hashBytes ke3) <*> (SessionKey <$> unbase64 hashBytes sessionKey))
    Right _ -> pure (Left DeserializeError)
    Left e -> pure (Left e)
