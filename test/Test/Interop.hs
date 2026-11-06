-- | Interoperability with @serenity-kit/opaque@ (opaque-ke compiled to
-- wasm), the OPAQUE implementation the wiki's browser client uses: its
-- client against this package's server, this package's client against its
-- server, and a registration made by one client with a login by the other.
-- Random passwords and identities, the empty context (serenity-kit passes
-- none), and Argon2id with parallelism 1 and the least parameters.
--
-- serenity-kit runs under Node, driven through @interop/serenity.mjs@ one
-- command per line. Where Node or the package (the repository's
-- node_modules, after @npm ci@) is missing, the tests say so and are
-- skipped.
module Test.Interop (spec) where

import Control.Exception (bracket)
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
import System.IO (BufferMode (..), Handle, hClose, hGetLine, hPutStrLn, hSetBuffering)
import System.Process (CreateProcess (..), StdStream (..), createProcess, proc, terminateProcess, waitForProcess)
import Test.Hspec
import Test.QuickCheck (Gen, choose, elements, generate, listOf, oneof)

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
spec = describe "with @serenity-kit/opaque (opaque-ke as wasm), under Node" $ do
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
