-- | Interoperability with @serenity-kit/opaque@ (opaque-ke compiled to
-- wasm), the OPAQUE implementation a browser client would use: its
-- client against this package's server, this package's client against its
-- server, and a registration made by one client with a login by the other.
-- Random passwords and identities, the empty context (serenity-kit passes
-- none), and Argon2id with parallelism 1 and the least parameters.
--
-- serenity-kit runs under Node, driven through @interop/serenity.mjs@ one
-- command per line. Where Node or the package (the repository's
-- node_modules, after @npm ci@) is missing, the tests say so and are
-- skipped.
--
-- The same server and client are also run against "Crypto.OPAQUE.Client"
-- as GHC's WebAssembly and JavaScript backends build it: the client that
-- calls serenity-kit, compiled (test-client\/Main.hs), under Node. It says
-- more than the tests above only where that client reads this package's
-- types: a t'Config' (Argon2id's memory in bytes against serenity-kit's in
-- KiB), the identities, the bytes of a password. The variable
-- @OPAQUE_HS_CLIENT@ is the command that starts it
-- (@sh scripts\/client.sh wasm serve@, or @js@); without it those tests are
-- skipped, and with it a client that does not start is a failure.
module Test.Interop (spec) where

import Control.Exception (IOException, bracket, try)
import Control.Monad (forM_, replicateM)
import Crypto.OPAQUE.Internal
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Char8 qualified as BC
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (encodeUtf8)
import System.Directory (doesFileExist, findExecutable)
import System.Environment (lookupEnv)
import System.IO (BufferMode (..), Handle, hClose, hGetLine, hPutStrLn, hSetBuffering)
import System.Process (CreateProcess (..), StdStream (..), createProcess, proc, terminateProcess, waitForProcess)
import Test.Hspec
import Test.QuickCheck (Gen, choose, elements, generate, listOf, oneof)

-- | The compiled client under Node, as two handles.
data Compiled = Compiled Handle Handle

-- | Run the compiled client for the test, where @OPAQUE_HS_CLIENT@ says
-- how. A client that was asked for and does not start fails the test.
withCompiled :: (Compiled -> IO ()) -> IO ()
withCompiled act =
  lookupEnv "OPAQUE_HS_CLIENT" >>= \case
    Nothing -> skipped
    Just command -> case words command of
      [] -> skipped
      program : arguments ->
        bracket
          (createProcess (proc program arguments) {std_in = CreatePipe, std_out = CreatePipe})
          (\(i, o, _, p) -> mapM_ hClose i >> mapM_ hClose o >> terminateProcess p >> waitForProcess p)
          $ \case
            (Just i, Just o, _, _) -> do
              hSetBuffering i LineBuffering
              try (hGetLine o) >>= \case
                Right "ready" -> act (Compiled i o)
                Right other -> expectationFailure ("the compiled client said " <> show other <> " where it should say ready")
                Left (e :: IOException) -> expectationFailure ("the compiled client did not start: " <> show e)
            _ -> expectationFailure "the compiled client did not start"
  where
    skipped = pendingWith "not run: OPAQUE_HS_CLIENT is not set (sh scripts/client.sh wasm serve, or js)"

-- | One command to the compiled client: the words of its answer, or the
-- name of the 'Error' its step failed with.
ask :: Compiled -> [String] -> IO (Either String [String])
ask (Compiled i o) command = do
  hPutStrLn i (unwords command)
  answer <- words <$> hGetLine o
  case answer of
    "ok" : results -> pure (Right results)
    ["fail", e] -> pure (Left e)
    _ -> expectationFailure ("the compiled client: " <> unwords answer) >> pure (Left "")

-- | Bytes as the compiled client takes and gives them: unpadded base64url
-- after a @b@, so that no bytes are still a word.
bytesArg :: ByteString -> String
bytesArg = ('b' :) . b64

-- | The bytes of a word the compiled client gave.
fromArg :: String -> IO ByteString
fromArg = \case
  'b' : encoded -> bytes encoded
  other -> expectationFailure ("not bytes: " <> other) >> pure BS.empty

-- | A configuration and identities as the compiled client takes them.
configArgs :: Config -> Identities -> [String]
configArgs c ids =
  [ bytesArg c.context
  , case c.ksf of
      Identity -> "identity"
      Argon2id {opsLimit, memLimit} -> "argon2id:" <> show opsLimit <> ":" <> show memLimit
  , maybe "-" bytesArg ids.client
  , maybe "-" bytesArg ids.server
  ]

-- | Argon2id with one pass and memory in bytes that is, or is not, a whole
-- number of KiB: libsodium takes bytes and serenity-kit KiB, and both
-- clients must round the same way.
someConfig :: Gen Config
someConfig = do
  memLimit <- elements [8192, 8192 + 512, 16384, 16384 + 1023]
  pure Config {context = "", ksf = Argon2id {opsLimit = 1, memLimit}}

-- | The compiled client registers with this package's server: the record
-- and the export key.
compiledRegisters :: Compiled -> Config -> ServerSetup -> Case -> IO (RegistrationRecord, ByteString)
compiledRegisters c cfg setup x = do
  [state, request] <- ok =<< ask c ["client-start-registration", bytesArg (encodeUtf8 x.password)]
  request' <- ok . decode =<< fromArg request
  response <- ok (registrationResponse setup (CredentialId (encodeUtf8 x.user)) request')
  [record, exportKey] <- ok =<< ask c (["client-finish-registration", state, bytesArg (encode response)] <> configArgs cfg (idsOf x))
  (,) <$> (ok . decode =<< fromArg record) <*> fromArg exportKey

-- | The compiled client logs in to this package's server with a password:
-- the export key, when both sides agree on a session key, or the name of
-- the error its last step failed with.
compiledLogsIn :: Compiled -> Config -> ServerSetup -> Maybe RegistrationRecord -> Case -> Text -> IO (Either String ByteString)
compiledLogsIn c cfg setup record x password = do
  [state, ke1] <- ok =<< ask c ["client-start-login", bytesArg (encodeUtf8 password)]
  ke1' <- ok . decode =<< fromArg ke1
  (sst, ke2) <- ok =<< serverRespond cfg setup record (CredentialId (encodeUtf8 x.user)) ke1' (idsOf x)
  ask c (["client-finish-login", state, bytesArg (encode ke2)] <> configArgs cfg (idsOf x)) >>= \case
    Right [ke3, sessionKey, exportKey] -> do
      ke3' <- ok . decode =<< fromArg ke3
      ours <- ok (serverFinish sst ke3')
      theirs <- fromArg sessionKey
      encode ours `shouldBe` theirs
      Right <$> fromArg exportKey
    Right other -> expectationFailure ("a login's answer: " <> unwords other) >> pure (Left "")
    Left e -> pure (Left e)

-- | serenity-kit under Node, as two handles.
data Serenity = Serenity Handle Handle

-- | Run the helper for the test, or say why the test cannot run.
withSerenity :: (Serenity -> IO ()) -> IO ()
withSerenity act = do
  node <- findExecutable "node"
  script <- doesFileExist helper
  case node of
    Nothing -> pendingWith "skipped: no node on PATH"
    Just _ | not script -> pendingWith ("skipped: no " <> helper)
    Just nodePath ->
      bracket
        (createProcess (proc nodePath [helper]) {std_in = CreatePipe, std_out = CreatePipe})
        (\(i, o, _, p) -> mapM_ hClose i >> mapM_ hClose o >> terminateProcess p >> waitForProcess p)
        $ \case
          (Just i, Just o, _, _) -> do
            hSetBuffering i LineBuffering
            first <- hGetLine o
            if first == "ready"
              then act (Serenity i o)
              else pendingWith "skipped: @serenity-kit/opaque is not installed (npm ci)"
          _ -> expectationFailure "the helper did not start"
  where
    helper = "interop/serenity.mjs"

-- | One command, and the words of its answer.
call :: Serenity -> [String] -> IO [String]
call (Serenity i o) command = do
  hPutStrLn i (unwords command)
  answer <- words <$> hGetLine o
  case answer of
    "error" : why -> expectationFailure ("serenity-kit: " <> unwords why) >> pure []
    _ -> pure answer

-- | Text as the helper takes it: UTF-8 in unpadded base64url, after a
-- @t@, so that empty text is still a word.
textArg :: Text -> String
textArg = ('t' :) . BC.unpack . Base64.encodeUnpadded . encodeUtf8

-- | An identity as the helper takes it: "-" for none.
identityArg :: Maybe Text -> String
identityArg = maybe "-" textArg

-- | A message's bytes from serenity-kit's base64url.
bytes :: String -> IO ByteString
bytes = either (\e -> expectationFailure e >> pure BS.empty) pure . Base64.decodeUnpadded . BC.pack

-- | A message's bytes in serenity-kit's base64url.
b64 :: ByteString -> String
b64 = BC.unpack . Base64.encodeUnpadded

ok :: (Show e) => Either e a -> IO a
ok = either (\e -> expectationFailure (show e) >> error "unreachable") pure

-- | The least Argon2id: one pass, 8 KiB, parallelism 1.
iterations, kib :: Int
iterations = 1
kib = 8

config :: Config
config = Config {context = "", ksf = Argon2id {opsLimit = fromIntegral iterations, memLimit = fromIntegral (kib * 1024)}}

-- | Random text: ASCII, and some letters beyond it, so that both sides are
-- seen to read UTF-8 alike.
someText :: Int -> Gen Text
someText most = do
  n <- choose (0, most)
  T.pack <$> replicateM n (oneof [choose (' ', '~'), elements "żółćπ∑日本🔑"])

data Case = Case
  { password :: Text
  , client :: Maybe Text
  , server :: Maybe Text
  , user :: Text
  }

someCase :: Gen Case
someCase = do
  password <- someText 40
  client <- oneof [pure Nothing, Just <$> someText 20]
  server <- oneof [pure Nothing, Just <$> someText 20]
  user <- T.pack <$> listOf (choose ('a', 'z'))
  pure Case {password, client, server, user = "user-" <> user}

idsOf :: Case -> Identities
idsOf c = Identities {client = encodeUtf8 <$> c.client, server = encodeUtf8 <$> c.server}

stretchArgs :: Case -> [String]
stretchArgs c = [show iterations, show kib, identityArg c.client, identityArg c.server]

-- | serenity-kit's client registers with this package's server: the record.
serenityRegisters :: Serenity -> ServerSetup -> Case -> IO (RegistrationRecord, ByteString)
serenityRegisters s setup c = do
  [state, request] <- call s ["client-start-registration", textArg c.password]
  request' <- ok . decode =<< bytes request
  response <- ok (registrationResponse setup (CredentialId (encodeUtf8 c.user)) request')
  [record, exportKey] <- call s (["client-finish-registration", state, b64 (encode response), textArg c.password] <> stretchArgs c)
  (,) <$> (ok . decode =<< bytes record) <*> bytes exportKey

-- | serenity-kit's client logs in to this package's server with a password:
-- the export key, when both sides agree on a session key.
serenityLogsIn :: Serenity -> ServerSetup -> RegistrationRecord -> Case -> Text -> IO (Maybe ByteString)
serenityLogsIn s setup record c password = do
  [state, ke1] <- call s ["client-start-login", textArg password]
  ke1' <- ok . decode =<< bytes ke1
  (sst, ke2) <- ok =<< serverRespond config setup (Just record) (CredentialId (encodeUtf8 c.user)) ke1' (idsOf c)
  call s (["client-finish-login", state, b64 (encode ke2), textArg password] <> stretchArgs c) >>= \case
    [ke3, sessionKey, exportKey] -> do
      ke3' <- ok . decode =<< bytes ke3
      SessionKey ours <- ok (serverFinish sst ke3')
      ourBytes <- pure (encode (SessionKey ours))
      theirs <- bytes sessionKey
      ourBytes `shouldBe` theirs
      Just <$> bytes exportKey
    _ -> pure Nothing

-- | This package's client registers with serenity-kit's server: the record.
haskellRegisters :: Serenity -> String -> Case -> IO (ByteString, ByteString)
haskellRegisters s setup c = do
  (st, request) <- ok =<< registrationRequest (encodeUtf8 c.password)
  [response] <- call s ["server-registration-response", setup, textArg c.user, b64 (encode request)]
  response' <- ok . decode =<< bytes response
  (record, exportKey) <- ok =<< finalizeRegistration config st response' (idsOf c)
  pure (encode record, encode exportKey)

-- | This package's client logs in to serenity-kit's server: the export
-- key, when both sides agree on a session key.
haskellLogsIn :: Serenity -> String -> ByteString -> Case -> Text -> IO (Maybe ByteString)
haskellLogsIn s setup record c password = do
  (st, ke1) <- ok =<< clientStart (encodeUtf8 password)
  [sst, ke2] <- call s ["server-start-login", setup, textArg c.user, b64 record, b64 (encode ke1), identityArg c.client, identityArg c.server]
  ke2' <- ok . decode =<< bytes ke2
  case clientFinish config st ke2' (idsOf c) of
    Left _ -> pure Nothing
    Right (ke3, key, exportKey) -> do
      [sessionKey] <- call s ["server-finish-login", sst, b64 (encode ke3), identityArg c.client, identityArg c.server]
      theirs <- bytes sessionKey
      encode key `shouldBe` theirs
      pure (Just (encode exportKey))

spec :: Spec
spec = serenitySpec >> compiledSpec

serenitySpec :: Spec
serenitySpec = describe "with @serenity-kit/opaque (opaque-ke as wasm), under Node" $ do
  it "its client registers and logs in with this server, and fails with a wrong password" $ withSerenity $ \s ->
    forM_ [1 :: Int .. 8] $ \_ -> do
      c <- generate someCase
      setup <- ok =<< generateServerSetup
      (record, exported) <- serenityRegisters s setup c
      serenityLogsIn s setup record c c.password `shouldReturn` Just exported
      serenityLogsIn s setup record c (c.password <> "!") `shouldReturn` Nothing

  it "this client registers and logs in with its server, and fails with a wrong password" $ withSerenity $ \s ->
    forM_ [1 :: Int .. 8] $ \_ -> do
      c <- generate someCase
      [setup] <- call s ["server-setup"]
      (record, exported) <- haskellRegisters s setup c
      haskellLogsIn s setup record c c.password `shouldReturn` Just exported
      haskellLogsIn s setup record c (c.password <> "!") `shouldReturn` Nothing

  it "a registration by either client logs in with the other, to the same export key" $ withSerenity $ \s ->
    forM_ [1 :: Int .. 8] $ \_ -> do
      c <- generate someCase
      setup <- ok =<< generateServerSetup
      -- serenity-kit registers; this client logs in.
      (record, exported) <- serenityRegisters s setup c
      (st, ke1) <- ok =<< clientStart (encodeUtf8 c.password)
      (sst, ke2) <- ok =<< serverRespond config setup (Just record) (CredentialId (encodeUtf8 c.user)) ke1 (idsOf c)
      (ke3, _, ExportKey ours) <- ok (clientFinish config st ke2 (idsOf c))
      _ <- ok (serverFinish sst ke3)
      encode (ExportKey ours) `shouldBe` exported
      -- This client registers; serenity-kit logs in.
      (st', request) <- ok =<< registrationRequest (encodeUtf8 c.password)
      response <- ok (registrationResponse setup (CredentialId (encodeUtf8 c.user)) request)
      (record', ExportKey exported') <- ok =<< finalizeRegistration config st' response (idsOf c)
      serenityLogsIn s setup record' c c.password `shouldReturn` Just (encode (ExportKey exported'))

  it "answers a login nobody has with a fake record its client fails on, as with a wrong password" $ withSerenity $ \s -> do
    c <- generate someCase
    setup <- ok =<< generateServerSetup
    [state, ke1] <- call s ["client-start-login", textArg c.password]
    ke1' <- ok . decode =<< bytes ke1
    (_, ke2) <- ok =<< serverRespond config setup Nothing (CredentialId (encodeUtf8 c.user)) ke1' (idsOf c)
    call s (["client-finish-login", state, b64 (encode ke2), textArg c.password] <> stretchArgs c) `shouldReturn` ["fail"]

compiledSpec :: Spec
compiledSpec = describe "with this package's client of the WebAssembly and JavaScript backends, compiled, under Node" $ do
  it "registers and logs in with this server, and fails with a wrong password" $ withCompiled $ \c ->
    forM_ [1 :: Int .. 8] $ \_ -> do
      x <- generate someCase
      cfg <- generate someConfig
      setup <- ok =<< generateServerSetup
      (record, exported) <- compiledRegisters c cfg setup x
      compiledLogsIn c cfg setup (Just record) x x.password `shouldReturn` Right exported
      compiledLogsIn c cfg setup (Just record) x (x.password <> "!") `shouldReturn` Left "EnvelopeRecoveryError"

  it "reads a configuration as the client over libsodium does: a registration by either logs in with the other" $ withCompiled $ \c ->
    forM_ [1 :: Int .. 8] $ \_ -> do
      x <- generate someCase
      cfg <- generate someConfig
      setup <- ok =<< generateServerSetup
      -- The compiled client registers; the client over libsodium logs in.
      (record, exported) <- compiledRegisters c cfg setup x
      (st, ke1) <- ok =<< clientStart (encodeUtf8 x.password)
      (sst, ke2) <- ok =<< serverRespond cfg setup (Just record) (CredentialId (encodeUtf8 x.user)) ke1 (idsOf x)
      (ke3, _, ExportKey ours) <- ok (clientFinish cfg st ke2 (idsOf x))
      _ <- ok (serverFinish sst ke3)
      encode (ExportKey ours) `shouldBe` exported
      -- The client over libsodium registers; the compiled client logs in.
      (st', request) <- ok =<< registrationRequest (encodeUtf8 x.password)
      response <- ok (registrationResponse setup (CredentialId (encodeUtf8 x.user)) request)
      (record', ExportKey exported') <- ok =<< finalizeRegistration cfg st' response (idsOf x)
      compiledLogsIn c cfg setup (Just record') x x.password `shouldReturn` Right (encode (ExportKey exported'))

  it "stretches with the memory it is given: a record made with other memory does not open" $ withCompiled $ \c -> do
    x <- generate someCase
    setup <- ok =<< generateServerSetup
    let withMemory memLimit = Config {context = "", ksf = Argon2id {opsLimit = 1, memLimit}}
    (record, exported) <- compiledRegisters c (withMemory 16384) setup x
    compiledLogsIn c (withMemory 8192) setup (Just record) x x.password `shouldReturn` Left "EnvelopeRecoveryError"
    -- Rounded down to the same 16 KiB, as libsodium rounds.
    compiledLogsIn c (withMemory (16384 + 1023)) setup (Just record) x x.password `shouldReturn` Right exported

  it "fails on the fake record of a login nobody has, as with a wrong password" $ withCompiled $ \c -> do
    x <- generate someCase
    setup <- ok =<< generateServerSetup
    compiledLogsIn c config setup Nothing x x.password `shouldReturn` Left "EnvelopeRecoveryError"

  it "says what it cannot do, and refuses what is invalid" $ withCompiled $ \c -> do
    x <- generate someCase
    setup <- ok =<< generateServerSetup
    (record, _) <- compiledRegisters c config setup x
    ask c ["client-start-login", bytesArg "\255\254"] `shouldReturn` Left "UnsupportedError"
    ask c ["client-start-registration", bytesArg (BS.replicate 65535 97)] `shouldReturn` Left "InvalidInputError"
    [state, ke1] <- ok =<< ask c ["client-start-login", bytesArg (encodeUtf8 x.password)]
    ke1' <- ok . decode =<< fromArg ke1
    (_, ke2) <- ok =<< serverRespond config setup (Just record) (CredentialId (encodeUtf8 x.user)) ke1' (idsOf x)
    let finishWith cfg ids message = ask c (["client-finish-login", state, bytesArg message] <> configArgs cfg ids)
        good = encode ke2
    finishWith config {context = "OPAQUE-POC"} (idsOf x) good `shouldReturn` Left "UnsupportedError"
    finishWith config {ksf = Identity} (idsOf x) good `shouldReturn` Left "UnsupportedError"
    finishWith config Identities {client = Just "\255", server = (idsOf x).server} good `shouldReturn` Left "UnsupportedError"
    finishWith config {ksf = Argon2id {opsLimit = 1, memLimit = 8191}} (idsOf x) good `shouldReturn` Left "KsfError"
    finishWith config {ksf = Argon2id {opsLimit = 0, memLimit = 8192}} (idsOf x) good `shouldReturn` Left "KsfError"
    finishWith config (idsOf x) (BS.take 100 good) `shouldReturn` Left "DeserializeError"
    -- An evaluated element that is no element of the group.
    finishWith config (idsOf x) (BS.replicate 32 255 <> BS.drop 32 good) `shouldReturn` Left "DeserializeError"
    -- A wrong MAC of the server's: this client cannot tell it from a
    -- wrong password, which the client over libsodium can.
    finishWith config (idsOf x) (BS.init good <> BS.singleton (BS.last good + 1)) `shouldReturn` Left "EnvelopeRecoveryError"
    -- The state still works after every refusal, and not once scrubbed.
    Right [_, _, _] <- finishWith config (idsOf x) good
    ask c ["scrub", state] `shouldReturn` Right []
    finishWith config (idsOf x) good `shouldReturn` Left "InvalidInputError"
