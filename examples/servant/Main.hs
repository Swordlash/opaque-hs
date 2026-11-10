-- | An example of opaque-hs in one program: a small HTTP server, written
-- with servant, that registers users and signs them in through OPAQUE, and
-- a client of it.
--
-- > cabal --project-file=cabal-examples.project run opaque-hs-servant-example
--
-- 'main' starts the server on a free port, runs the client against it while
-- the server is up, and prints what each request came to: a registration
-- with a first name, a last name and a date of birth; logins with a wrong
-- password, for a name nobody has, and with the right password; and
-- @GET \/me@, which gives the registered details back to a signed-in user
-- only.
--
-- The server never sees a password. It keeps everything in memory: its
-- t'ServerSetup', a record and the details per user, the logins under way,
-- and the tokens of the users signed in. What a real application adds is
-- said where it is left out: TLS, a database, a time limit on a login
-- under way.
--
-- The program imports "Crypto.OPAQUE" because it is both sides. A program
-- that is only the client imports "Crypto.OPAQUE.Client", which has the
-- client's four steps under the same names, also in a browser.
module Main (main) where

import Control.Concurrent.STM (TVar, atomically, modifyTVar', newTVarIO, readTVar, readTVarIO, writeTVar)
import Control.Monad (unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), except, runExceptT, withExceptT)
import Crypto.OPAQUE
import Crypto.OPAQUE.Sodium (randomBytes)
import Data.Aeson (FromJSON (..), ToJSON (..), Value (String), withText)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Lazy.Char8 qualified as LBC
import Data.Either (isLeft, isRight)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time (Day, fromGregorian)
import Data.Word (Word64)
import GHC.Generics (Generic)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (statusCode)
import Network.Wai.Handler.Warp qualified as Warp
import Servant
import Servant.Client (BaseUrl (..), ClientEnv, ClientError (..), ClientM, Scheme (..), client, mkClientEnv, responseStatusCode, runClientM)
import System.Exit (exitFailure)
import System.IO (BufferMode (..), hSetBuffering, stdout)

--------------------------------------------------------------------------------
-- The API

-- | What a user gives at registration and gets back from @GET \/me@.
data UserInfo = UserInfo
  { firstName :: Text
  , lastName :: Text
  , dateOfBirth :: Day
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | An OPAQUE message as JSON carries it: its bytes ('encode') in unpadded
-- base64url.
newtype Bytes = Bytes ByteString

instance ToJSON Bytes where
  toJSON (Bytes b) = String (decodeUtf8 (Base64.encodeUnpadded b))

instance FromJSON Bytes where
  parseJSON = withText "base64url" (either fail (pure . Bytes) . Base64.decodeUnpadded . encodeUtf8)

-- | A message to send.
sent :: (Encoding a) => a -> Bytes
sent = Bytes . encode

-- | A message that arrived: 'decode' checks its length and its group
-- elements.
received :: (Encoding a) => Bytes -> Either Error a
received (Bytes b) = decode b

-- | Argon2id's passes and memory in bytes. The client stretches, so the
-- server tells it with which parameters, at registration and at each login:
-- the ones the user's record was made with.
data Stretching = Stretching {passes :: Word64, memory :: Word64}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data RegisterStart = RegisterStart {username :: Text, request :: Bytes}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data RegisterStarted = RegisterStarted {response :: Bytes, stretching :: Stretching}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data RegisterFinish = RegisterFinish {username :: Text, record :: Bytes, info :: UserInfo}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data LoginStart = LoginStart {username :: Text, ke1 :: Bytes}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | @attempt@ names the login under way, so that the last message finds
-- the server's state of it.
data LoginStarted = LoginStarted {attempt :: Text, ke2 :: Bytes, stretching :: Stretching}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data LoginFinish = LoginFinish {attempt :: Text, ke3 :: Bytes}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

data LoggedIn = LoggedIn {token :: Text}
  deriving stock (Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | A registration is two requests and a login is two: OPAQUE's messages,
-- one round trip each. @GET \/me@ takes the token a login gave, as
-- @Authorization: Bearer TOKEN@.
type Api =
  "register" :> "start" :> ReqBody '[JSON] RegisterStart :> Post '[JSON] RegisterStarted
    :<|> "register" :> "finish" :> ReqBody '[JSON] RegisterFinish :> PostNoContent
    :<|> "login" :> "start" :> ReqBody '[JSON] LoginStart :> Post '[JSON] LoginStarted
    :<|> "login" :> "finish" :> ReqBody '[JSON] LoginFinish :> Post '[JSON] LoggedIn
    :<|> "me" :> Header "Authorization" Text :> Get '[JSON] UserInfo

-- | What both sides must agree on. The context is empty so that a browser's
-- client ("Crypto.OPAQUE.Client" over serenity-kit) could sign in too.
configOf :: Stretching -> Config
configOf s = Config {context = "", ksf = Argon2id {opsLimit = s.passes, memLimit = s.memory}}

--------------------------------------------------------------------------------
-- The server

-- | A user: the OPAQUE record, which says nothing about the password to
-- whoever lacks the server's setup, and the details given at registration.
data Account = Account {record :: RegistrationRecord, info :: UserInfo}

-- | Everything the server knows, in memory. A real server keeps the setup
-- and the accounts in its database, and loses neither: without the setup
-- every record is useless.
data Memory = Memory
  { setup :: ServerSetup
  , accounts :: TVar (Map Text Account)
  , attempts :: TVar (Map Text (Text, ServerLoginState))
  -- ^ The logins under way, by their name: the user and the server's state
  -- between KE2 and KE3. A real server also forgets one after a minute.
  , sessions :: TVar (Map Text Text)
  -- ^ The user of each token a login gave.
  }

newMemory :: IO Memory
newMemory = do
  setup <- either (fail . show) pure =<< generateServerSetup
  Memory setup <$> newTVarIO Map.empty <*> newTVarIO Map.empty <*> newTVarIO Map.empty

-- | What new records are stretched with. A real server stores the
-- parameters beside each record, so that it can raise them later for new
-- records without breaking the old ones.
stretchingNow :: Stretching
stretchingNow = Stretching {passes = 2, memory = 64 * 1024 * 1024}

-- | The server's name for a user's record. It must never change for a
-- record, so a real server uses an identifier of its own, not a name the
-- user may change.
credentialId :: Text -> CredentialId
credentialId = CredentialId . encodeUtf8

-- | A random name for a login under way, or a token: 32 random bytes.
randomName :: IO Text
randomName = decodeUtf8 . Base64.encodeUnpadded <$> randomBytes 32

-- | An OPAQUE step that failed on what the client sent is a bad request.
orBadRequest :: Either Error a -> Handler a
orBadRequest = either (\e -> throwError err400 {errBody = LBC.pack (show e)}) pure

handlers :: Memory -> Server Api
handlers m = registerStart :<|> registerFinish :<|> loginStart :<|> loginFinish :<|> me
  where
    -- The server evaluates the OPRF on the blinded password. It keeps
    -- nothing between the two requests of a registration.
    registerStart r = do
      request <- orBadRequest (received r.request)
      response <- orBadRequest (registrationResponse m.setup (credentialId r.username) request)
      pure RegisterStarted {response = sent response, stretching = stretchingNow}

    -- The client made the record; the server stores it, with the details.
    registerFinish r = do
      record <- orBadRequest (received r.record)
      taken <- liftIO . atomically $ do
        known <- readTVar m.accounts
        if Map.member r.username known
          then pure True
          else False <$ writeTVar m.accounts (Map.insert r.username Account {record, info = r.info} known)
      when taken (throwError err409 {errBody = "the name is taken"})
      pure NoContent

    -- For a name nobody has, 'serverRespond' is given no record and answers
    -- with a fake one, so that the answer does not say whether the user
    -- exists. The client then fails as with a wrong password.
    loginStart r = do
      ke1 <- orBadRequest (received r.ke1)
      account <- liftIO (Map.lookup r.username <$> readTVarIO m.accounts)
      (state, ke2) <-
        orBadRequest
          =<< liftIO (serverRespond (configOf stretchingNow) m.setup (fmap (\a -> a.record) account) (credentialId r.username) ke1 defaultIdentities)
      attempt <- liftIO randomName
      liftIO . atomically $ modifyTVar' m.attempts (Map.insert attempt (r.username, state))
      pure LoginStarted {attempt, ke2 = sent ke2, stretching = stretchingNow}

    -- KE3 proves that the client knew the password. A login under way has
    -- one try. Both sides now hold the same session key; this server, as
    -- most do over TLS, does not use it and gives a random token instead.
    loginFinish r = do
      ke3 <- orBadRequest (received r.ke3)
      found <- liftIO . atomically $ do
        waiting <- readTVar m.attempts
        writeTVar m.attempts (Map.delete r.attempt waiting)
        pure (Map.lookup r.attempt waiting)
      case found of
        Nothing -> throwError err401
        Just (username, state) -> case serverFinish state ke3 of
          Left _ -> liftIO (scrub state) >> throwError err401
          Right sessionKey -> do
            liftIO (scrub sessionKey >> scrub state)
            token <- liftIO randomName
            liftIO . atomically $ modifyTVar' m.sessions (Map.insert token username)
            pure LoggedIn {token}

    me authorization = do
      username <- case T.stripPrefix "Bearer " =<< authorization of
        Nothing -> throwError err401
        Just token -> liftIO (Map.lookup token <$> readTVarIO m.sessions) >>= maybe (throwError err401) pure
      liftIO (Map.lookup username <$> readTVarIO m.accounts) >>= maybe (throwError err404) (\a -> pure a.info)

--------------------------------------------------------------------------------
-- The client

postRegisterStart :: RegisterStart -> ClientM RegisterStarted
postRegisterFinish :: RegisterFinish -> ClientM NoContent
postLoginStart :: LoginStart -> ClientM LoginStarted
postLoginFinish :: LoginFinish -> ClientM LoggedIn
getMe :: Maybe Text -> ClientM UserInfo
postRegisterStart :<|> postRegisterFinish :<|> postLoginStart :<|> postLoginFinish :<|> getMe = client (Proxy :: Proxy Api)

-- | Why the client's part of a registration or a login stopped: an OPAQUE
-- step failed, or a request did.
data Failure = Step Error | Request ClientError

step :: Either Error a -> ExceptT Failure IO a
step = withExceptT Step . except

ask :: ClientEnv -> ClientM a -> ExceptT Failure IO a
ask env call = ExceptT (first Request <$> runClientM call env)

-- | Register: blind the password, send it, and with the server's response
-- make the record the server stores. The password goes nowhere.
register :: ClientEnv -> Text -> ByteString -> UserInfo -> IO (Either Failure ())
register env username password info = runExceptT $ do
  (state, blinded) <- step =<< liftIO (registrationRequest password)
  started <- ask env (postRegisterStart RegisterStart {username, request = sent blinded})
  response <- step (received started.response)
  (record, exportKey) <- step =<< liftIO (finalizeRegistration (configOf started.stretching) state response defaultIdentities)
  -- The export key is a secret only this client can compute, the same at
  -- every login: an application can encrypt the user's data with it.
  liftIO (scrub state >> scrub exportKey)
  _ <- ask env (postRegisterFinish RegisterFinish {username, record = sent record, info})
  pure ()

-- | Log in: the token for the requests that follow. 'clientFinish' fails
-- on a wrong password, and on a server that is not the one the user
-- registered with, before anything is sent back.
login :: ClientEnv -> Text -> ByteString -> IO (Either Failure Text)
login env username password = runExceptT $ do
  (state, ke1) <- step =<< liftIO (clientStart password)
  started <- ask env (postLoginStart LoginStart {username, ke1 = sent ke1})
  ke2 <- step (received started.ke2)
  (ke3, sessionKey, exportKey) <- step (clientFinish (configOf started.stretching) state ke2 defaultIdentities)
  liftIO (scrub state >> scrub sessionKey >> scrub exportKey)
  loggedIn <- ask env (postLoginFinish LoginFinish {attempt = started.attempt, ke3 = sent ke3})
  pure loggedIn.token

userInfo :: ClientEnv -> Maybe Text -> IO (Either Failure UserInfo)
userInfo env token = runExceptT (ask env (getMe (("Bearer " <>) <$> token)))

--------------------------------------------------------------------------------
-- The program

-- | How a failure reads in the program's output.
refused :: Failure -> String
refused = \case
  Step e -> "refused by the client: " <> show e
  Request (FailureResponse _ r) -> "refused by the server: HTTP " <> show (statusCode (responseStatusCode r))
  Request e -> "the request failed: " <> show e

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  manager <- newManager defaultManagerSettings
  memory <- newMemory
  -- withApplication is a bracket: the server is up on a free port while
  -- the client's part runs, and is stopped afterwards. Plain HTTP on the
  -- loopback interface; a real server speaks TLS.
  outcomes <- Warp.withApplication (pure (serve (Proxy :: Proxy Api) (handlers memory))) $ \port -> do
    let env = mkClientEnv manager (BaseUrl Http "127.0.0.1" port "")
        password = "correct horse battery staple"
        ada = UserInfo {firstName = "Ada", lastName = "Lovelace", dateOfBirth = fromGregorian 1815 12 10}
        say what = either refused id >>> \outcome -> putStrLn (what <> ": " <> outcome)

    registered <- register env "ada" password ada
    say "register ada" ("registered" <$ registered)

    again <- register env "ada" "another password" ada
    say "register ada again" ("registered" <$ again)

    wrong <- login env "ada" "a wrong password"
    say "log in as ada with a wrong password" ("logged in" <$ wrong)

    nobody <- login env "grace" password
    say "log in as grace, whom the server does not know" ("logged in" <$ nobody)

    loggedIn <- login env "ada" password
    say "log in as ada" ("logged in, with a token" <$ loggedIn)

    mine <- userInfo env (either (const Nothing) Just loggedIn)
    say "GET /me with the token" ((\u -> T.unpack u.firstName <> " " <> T.unpack u.lastName <> ", born " <> show u.dateOfBirth) <$> mine)

    anonymous <- userInfo env Nothing
    say "GET /me without a token" ("answered" <$ anonymous)

    pure
      [ isRight registered
      , isLeft again
      , isLeft wrong
      , isLeft nobody
      , isRight loggedIn
      , either (const False) (== ada) mine
      , isLeft anonymous
      ]
  unless (and outcomes) $ do
    putStrLn "The example did not go as it should."
    exitFailure
  where
    f >>> g = g . f
