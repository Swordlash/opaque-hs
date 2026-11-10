{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}

-- | The client of GHC's WebAssembly and JavaScript backends
-- ("Crypto.OPAQUE.Client" over @\@serenity-kit\/opaque@), compiled, as a
-- program for Node. It has two uses.
--
-- Run with no argument, it tests itself: a registration and logins with
-- serenity-kit's own server, in the same process. That needs nothing but
-- Node and @npm ci@, and says that the client loads the library and calls
-- it rightly. It cannot say that the client reads a t'Config' as the
-- client over libsodium does: serenity-kit's server never runs the key
-- stretching.
--
-- Run with the argument @serve@, it answers one command per line of
-- standard input with one line of standard output, and the native test
-- suite (test-native\/Test\/Interop.hs) drives it against this package's
-- server and its client over libsodium. Its first line is @ready@. Words
-- are separated by spaces:
--
-- > client-start-registration PASSWORD                                  -> ok STATE REQUEST
-- > client-finish-registration STATE RESPONSE CONTEXT KSF CLIENT SERVER -> ok RECORD EXPORT_KEY
-- > client-start-login PASSWORD                                         -> ok STATE KE1
-- > client-finish-login STATE KE2 CONTEXT KSF CLIENT SERVER             -> ok KE3 SESSION_KEY EXPORT_KEY
-- > scrub STATE                                                         -> ok
-- > client-finish-registration-held STATE RESPONSE CONTEXT KSF CLIENT SERVER -> ok RECORD DERIVED
-- > client-finish-login-held STATE KE2 CONTEXT KSF CLIENT SERVER             -> ok KE3 SESSION_KEY DERIVED
--
-- The two @-held@ commands are the steps of
-- "Crypto.OPAQUE.Client.WebCrypto", which keep the export key in WebCrypto.
-- Nobody can read that key, so they answer with what HKDF-SHA-512 derives
-- from it, 64 bytes, with no salt and the info @opaque-hs test@; the native
-- side derives the same from its own export key. DERIVED is @-@ where
-- there is no WebCrypto.
--
-- A step that fails answers @fail@ and the 'Error' (@fail
-- EnvelopeRecoveryError@), and a command that cannot be read answers
-- @error@ and why. Bytes (a password, a message, a key, the context, an
-- identity) are unpadded base64url after a @b@, so that no bytes are still
-- a word; @-@ is no identity. KSF is @identity@, or @argon2id:PASSES:BYTES@.
-- A STATE is a name the program gives a state it keeps (@s1@, @s2@): the
-- states of this client have no encoding.
module Main (main) where

import Control.Exception (throwIO)
import Control.Monad (unless, when)
import Crypto.OPAQUE.Client
import Crypto.OPAQUE.Client.WebCrypto
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Char8 qualified as BC
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Halogen.JSBits (JSText, JSVal, Safety (..), browserJS, fromJSText, isNull, jsValText, toJSText)
import Halogen.JSBits.Promise (Promise, wait)
import System.Environment (getArgs)
import Text.Read (readMaybe)

$( browserJS
     ["test-client/driver.js"]
     [ ("js_line", "opaque_hs_test_line", Safe, [t|IO (Promise JSVal)|])
     , ("js_say", "opaque_hs_test_say", Safe, [t|JSText -> IO ()|])
     , ("js_server", "opaque_hs_test_server", Safe, [t|IO (Promise Text)|])
     , ("js_registration_response", "opaque_hs_test_registration_response", Safe, [t|JSText -> JSText -> JSText -> IO JSText|])
     , ("js_start_login", "opaque_hs_test_start_login", Safe, [t|JSText -> JSText -> JSText -> JSText -> IO JSText|])
     , ("js_finish_login", "opaque_hs_test_finish_login", Safe, [t|JSText -> JSText -> IO JSText|])
     , ("js_key_facts", "opaque_hs_test_key_facts", Safe, [t|JSVal -> IO JSText|])
     , ("js_derive", "opaque_hs_test_derive", Safe, [t|JSVal -> JSText -> IO (Promise Text)|])
     , ("js_export_refused", "opaque_hs_test_export_refused", Safe, [t|JSVal -> IO (Promise Bool)|])
     , ("js_import", "opaque_hs_test_import", Safe, [t|JSText -> IO (Promise JSVal)|])
     ]
 )

main :: IO ()
main =
  getArgs >>= \case
    ["serve"] -> serve
    [] -> selfTest
    other -> failure ("unknown arguments: " <> unwords other)

#if defined(wasm32_HOST_ARCH)
-- On WebAssembly the program is a reactor: a command's main cannot wait for
-- a promise. interop/client-wasm.mjs calls this export and waits for it.
foreign export javascript "hs_test" main :: IO ()
#endif

say :: String -> IO ()
say = js_say . toJSText . T.pack

failure :: String -> IO a
failure = throwIO . userError

--------------------------------------------------------------------------------
-- One command a line

-- | A state the program keeps for the test, under a name.
data Held = Registering ClientRegState | LoggingIn ClientLoginState

data Table = Table {next :: Int, held :: Map String Held}

serve :: IO ()
serve = do
  table <- newIORef Table {next = 1, held = Map.empty}
  say "ready"
  let loop = do
        line <- wait =<< js_line
        unless (isNull line) $ do
          say =<< command table (words (T.unpack (jsValText line)))
          loop
  loop

-- | Keep a state, and give its name.
hold :: IORef Table -> Held -> IO String
hold table state = atomicModifyIORef' table $ \t ->
  let name = "s" <> show t.next
   in (Table {next = t.next + 1, held = Map.insert name state t.held}, name)

command :: IORef Table -> [String] -> IO String
command table = \case
  ["client-start-registration", password]
    | Just password' <- bytesArg password ->
        registrationRequest password' >>= answered (\(state, request) -> do name <- hold table (Registering state); pure [name, word (encode request)])
  ["client-finish-registration", name, response, context, ksf, client, server]
    | Just config <- configArg context ksf
    , Just ids <- Identities <$> identityArg client <*> identityArg server
    , Just response' <- bytesArg response ->
        lookupHeld name >>= \case
          Just (Registering state) -> case decode response' of
            Left e -> pure ("fail " <> show e)
            Right response'' -> finalizeRegistration config state response'' ids >>= answered (\(record, exportKey) -> pure [word (encode record), word (encode exportKey)])
          _ -> pure "error no such registration"
  ["client-start-login", password]
    | Just password' <- bytesArg password ->
        clientStart password' >>= answered (\(state, ke1) -> do name <- hold table (LoggingIn state); pure [name, word (encode ke1)])
  ["client-finish-login", name, ke2, context, ksf, client, server]
    | Just config <- configArg context ksf
    , Just ids <- Identities <$> identityArg client <*> identityArg server
    , Just ke2' <- bytesArg ke2 ->
        lookupHeld name >>= \case
          Just (LoggingIn state) ->
            answered (\(ke3, sessionKey, exportKey) -> pure [word (encode ke3), word (encode sessionKey), word (encode exportKey)]) (decode ke2' >>= \k -> clientFinish config state k ids)
          _ -> pure "error no such login"
  ["client-finish-registration-held", name, response, context, ksf, client, server]
    | Just config <- configArg context ksf
    , Just ids <- Identities <$> identityArg client <*> identityArg server
    , Just response' <- bytesArg response ->
        lookupHeld name >>= \case
          Just (Registering state) -> case decode response' of
            Left e -> pure ("fail " <> show e)
            Right response'' ->
              finalizeRegistrationWebCrypto (DeriveBits :| []) config state response'' ids
                >>= answered (\(record, key) -> (\derived -> [word (encode record), derived]) <$> derivedWord key)
          _ -> pure "error no such registration"
  ["client-finish-login-held", name, ke2, context, ksf, client, server]
    | Just config <- configArg context ksf
    , Just ids <- Identities <$> identityArg client <*> identityArg server
    , Just ke2' <- bytesArg ke2 ->
        lookupHeld name >>= \case
          Just (LoggingIn state) -> case decode ke2' of
            Left e -> pure ("fail " <> show e)
            Right ke2'' ->
              clientFinishWebCrypto (DeriveBits :| []) config state ke2'' ids
                >>= answered (\(ke3, sessionKey, key) -> (\derived -> [word (encode ke3), word (encode sessionKey), derived]) <$> derivedWord key)
          _ -> pure "error no such login"
  ["scrub", name] ->
    lookupHeld name >>= \case
      Just (Registering state) -> "ok" <$ scrub state
      Just (LoggingIn state) -> "ok" <$ scrub state
      Nothing -> pure "error no such state"
  other -> pure ("error cannot read: " <> unwords other)
  where
    lookupHeld name = Map.lookup name . (.held) <$> readIORef table
    answered :: (a -> IO [String]) -> Either Error a -> IO String
    answered wordsOf = either (pure . ("fail " <>) . show) (fmap (unwords . ("ok" :)) . wordsOf)

word :: ByteString -> String
word = ('b' :) . BC.unpack . Base64.encodeUnpadded

-- | The info both sides derive with.
derivedInfo :: Text
derivedInfo = "opaque-hs test"

-- | What HKDF-SHA-512 derives from a held export key, in base64url.
derive :: ExportCryptoKey -> IO Text
derive (ExportCryptoKey key) = wait =<< js_derive key (toJSText derivedInfo)

-- | That, as a word of an answer: @-@ where no key is held.
derivedWord :: Maybe ExportCryptoKey -> IO String
derivedWord = maybe (pure "-") (fmap (('b' :) . T.unpack) . derive)

bytesArg :: String -> Maybe ByteString
bytesArg = \case
  'b' : encoded -> either (const Nothing) Just (Base64.decodeUnpadded (BC.pack encoded))
  _ -> Nothing

identityArg :: String -> Maybe (Maybe ByteString)
identityArg = \case
  "-" -> Just Nothing
  given -> Just <$> bytesArg given

configArg :: String -> String -> Maybe Config
configArg context ksf = Config <$> bytesArg context <*> ksfArg
  where
    ksfArg = case break (== ':') ksf of
      ("identity", "") -> Just Identity
      ("argon2id", ':' : limits)
        | (passes, ':' : bytes) <- break (== ':') limits -> Argon2id <$> readMaybe passes <*> readMaybe bytes
      _ -> Nothing

--------------------------------------------------------------------------------
-- The test of itself

selfTest :: IO ()
selfTest = do
  setup <- toJSText <$> (wait =<< js_server)
  let config = Config {context = "", ksf = Argon2id {opsLimit = 1, memLimit = 8192}}
      password = "correct horse \197\188\195\179\197\130\196\135" -- ASCII and UTF-8 beyond it
      user = toJSText "user-1"
      serverStarts record ke1 = do
        answer <- fromJSText <$> js_start_login setup user (text64 record) (text64 (encode ke1))
        case T.words answer of
          [state, ke2] -> (toJSText state,) <$> (expectRight "KE2 decodes" . decode =<< unbase64 ke2)
          _ -> failure "serenity-kit's server did not start the login"

  (registering, request) <- expectRight "a registration starts" =<< registrationRequest password
  response <- expectRight "the response decodes" . decode =<< unbase64 . fromJSText =<< js_registration_response setup user (text64 (encode request))
  (record, exported) <- expectRight "a registration finishes" =<< finalizeRegistration config registering response defaultIdentities
  check "a record has its length" (BS.length (encode record) == 192)

  (loggingIn, ke1) <- expectRight "a login starts" =<< clientStart password
  (serverState, ke2) <- serverStarts (encode record) ke1
  (ke3, sessionKey, exportKey) <- expectRight "a login with the password finishes" (clientFinish config loggingIn ke2 defaultIdentities)
  theirs <- unbase64 . fromJSText =<< js_finish_login serverState (text64 (encode ke3))
  check "the server agrees on the session key" (encode sessionKey == theirs && BS.length theirs == 64)
  check "a login gives the registration's export key" (encode exportKey == encode exported)
  check "the same step twice gives the same result" . (== Right (encode ke3)) $
    (\(k, _, _) -> encode k) <$> clientFinish config loggingIn ke2 defaultIdentities

  check "another memory is another key: the configuration is used" . (== Left EnvelopeRecoveryError) $
    () <$ clientFinish config {ksf = Argon2id {opsLimit = 1, memLimit = 16384}} loggingIn ke2 defaultIdentities
  check "a context is unsupported" . (== Left UnsupportedError) $
    () <$ clientFinish config {context = "x"} loggingIn ke2 defaultIdentities
  check "no stretching is unsupported" . (== Left UnsupportedError) $
    () <$ clientFinish config {ksf = Identity} loggingIn ke2 defaultIdentities
  check "less memory than Argon2id takes is a KSF error" . (== Left KsfError) $
    () <$ clientFinish config {ksf = Argon2id {opsLimit = 1, memLimit = 8191}} loggingIn ke2 defaultIdentities
  check "an identity that is not UTF-8 is unsupported" . (== Left UnsupportedError) $
    () <$ clientFinish config loggingIn ke2 defaultIdentities {client = Just "\255"}

  (wrong, wrongKe1) <- expectRight "a login with a wrong password starts" =<< clientStart (password <> "!")
  (_, wrongKe2) <- serverStarts (encode record) wrongKe1
  check "a wrong password fails as the envelope's recovery" . (== Left EnvelopeRecoveryError) $
    () <$ clientFinish config wrong wrongKe2 defaultIdentities

  (nobody, nobodyKe1) <- expectRight "a login nobody has starts" =<< clientStart password
  (_, fakeKe2) <- serverStarts "" nobodyKe1
  check "a login nobody has fails as a wrong password" . (== Left EnvelopeRecoveryError) $
    () <$ clientFinish config nobody fakeKe2 defaultIdentities

  notUtf8 <- clientStart "\255\254"
  check "a password that is not UTF-8 is unsupported" (either (== UnsupportedError) (const False) notUtf8)

  -- The same steps with the export key held in WebCrypto.
  (registering', request') <- expectRight "a second registration starts" =<< registrationRequest password
  response' <- expectRight "its response decodes" . decode =<< unbase64 . fromJSText =<< js_registration_response setup user (text64 (encode request'))
  (record', heldAtRegistration) <-
    expectRight "a registration finishes with its export key held" =<< finalizeRegistrationWebCrypto (DeriveBits :| []) config registering' response' defaultIdentities
  registered <- maybe (failure "failed: there is WebCrypto, so a registration holds its export key") pure heldAtRegistration
  let ExportCryptoKey registeredKey = registered
  check "the held key is HKDF's, cannot be exported, and has the usage asked for" . (== "HKDF false deriveBits") . fromJSText =<< js_key_facts registeredKey
  check "WebCrypto refuses to export the held key" =<< (wait =<< js_export_refused registeredKey)

  (loggingIn', ke1') <- expectRight "a login to the second record starts" =<< clientStart password
  (serverState', ke2') <- serverStarts (encode record') ke1'
  (ke3', sessionKey', heldAtLogin) <-
    expectRight "a login finishes with its export key held" =<< clientFinishWebCrypto (DeriveBits :| [DeriveKey]) config loggingIn' ke2' defaultIdentities
  theirs' <- unbase64 . fromJSText =<< js_finish_login serverState' (text64 (encode ke3'))
  check "the server agrees on the session key of that login" (encode sessionKey' == theirs')
  loggedIn <- maybe (failure "failed: there is WebCrypto, so a login holds its export key") pure heldAtLogin
  let ExportCryptoKey loggedInKey = loggedIn
  check "a key held for two usages has both" . (== "HKDF false deriveKey,deriveBits") . fromJSText =<< js_key_facts loggedInKey
  fromRegistration <- derive registered
  fromLogin <- derive loggedIn
  check "the key held at a login derives what the key held at the registration derives" (fromLogin == fromRegistration && T.length fromLogin == 86)
  -- The step that gives the export key as bytes, on the same state and
  -- KE2, gives the key that is held.
  (_, _, plain) <- expectRight "the same login finishes with its export key as bytes" (clientFinish config loggingIn' ke2' defaultIdentities)
  imported <- wait =<< js_import (text64 (encode plain))
  fromBytes <- derive (ExportCryptoKey imported)
  check "the held key is the export key" (fromBytes == fromLogin)
  held <- clientFinishWebCrypto (DeriveBits :| []) config {context = "x"} loggingIn' ke2' defaultIdentities
  check "a context is unsupported with the key held too" (either (== UnsupportedError) (const False) held)
  (wrong', wrongKe1') <- expectRight "another login with a wrong password starts" =<< clientStart (password <> "?")
  (_, wrongKe2') <- serverStarts (encode record') wrongKe1'
  refused <- clientFinishWebCrypto (DeriveBits :| []) config wrong' wrongKe2' defaultIdentities
  check "a wrong password fails with the key held too, and holds none" (either (== EnvelopeRecoveryError) (const False) refused)

  scrub loggingIn
  check "a scrubbed state is refused" . (== Left InvalidInputError) $
    () <$ clientFinish config loggingIn ke2 defaultIdentities
  scrub exportKey
  check "a scrubbed key is zero" (encode exportKey == BS.replicate 64 0)
  say "opaque-client-test: the client's test of itself passed"
  where
    text64 = toJSText . T.pack . BC.unpack . Base64.encodeUnpadded
    unbase64 :: Text -> IO ByteString
    unbase64 = either failure pure . Base64.decodeUnpadded . BC.pack . T.unpack
    check what holds = when (not holds) (failure ("failed: " <> what))
    expectRight :: String -> Either Error a -> IO a
    expectRight what = either (\e -> failure ("failed: " <> what <> ": " <> show e)) pure
