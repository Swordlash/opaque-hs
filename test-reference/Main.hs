-- | This package against a second implementation of OPAQUE: libopaque, and
-- the liboprf it is written over, in C ("Reference", @scripts/reference.sh@).
--
-- Three kinds of comparison:
--
-- * The OPRF's functions (RFC 9497) one by one, on random inputs: both
--   sides compute the same bytes.
-- * A whole registration and a whole login with the same random values on
--   both sides: every message, the record, the session key and the export
--   key are the same bytes. libopaque draws the values the test scripts
--   for it; this package takes them as arguments
--   ("Crypto.OPAQUE.Internal"'s functions that end in @With@).
-- * One side's client against the other's server, with real random values
--   on both: they agree on the session key, and a wrong password fails.
--
-- libopaque stretches with Argon2id at libsodium's interactive limits (2
-- passes, 64 MiB), parallelism 1 and a salt of 16 zero bytes, which is
-- 'referenceKsf' here. It keeps a random OPRF key for each client, where
-- this package derives the key from the server's seed and the client's
-- credential identifier; the scripted runs hand libopaque the derived key
-- as its "random" one. An identity of no bytes is no identity for
-- libopaque, so the identities here are absent or not empty.
module Main (main) where

import Control.Monad (forM_, replicateM)
import Crypto.OPAQUE.Internal
import Crypto.OPAQUE.Kdf qualified as Kdf
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Sodium (randomBytes, randomScalar)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Maybe (fromMaybe)
import Reference (ClientEnd (..), Ids (..), Script (..), ServerAnswer (..))
import Reference qualified as Ref
import Test.Hspec hiding (context)
import Test.QuickCheck (Gen, choose, frequency, generate, vectorOf)

main :: IO ()
main = do
  Ref.install
  hspec $ do
    describe "the OPRF's functions, against liboprf" oprfSpec
    describe "a registration and a login with the same random values, against libopaque" scriptedSpec
    describe "one side's client with the other's server, with real random values" mixedSpec

-- | The key stretching libopaque uses: Argon2id at libsodium's interactive
-- limits.
referenceKsf :: Ksf
referenceKsf = Argon2id {opsLimit = 2, memLimit = 64 * 1024 * 1024}

orFail :: (Show e) => String -> Either e a -> IO a
orFail what = either (\e -> expectationFailure (what <> ": " <> show e) >> error "unreachable") pure

-- | A step of the reference, which must succeed.
ref :: String -> IO (Either Int a) -> IO a
ref what step = step >>= orFail ("libopaque's " <> what)

-- | Two values are the same bytes; a failure shows them in hexadecimal.
sameBytes :: ByteString -> ByteString -> Expectation
sameBytes theirs ours = hex theirs `shouldBe` hex ours
  where
    hex = concatMap (\w -> let (h, l) = w `divMod` 16 in [digit h, digit l]) . BS.unpack
    digit n = "0123456789abcdef" !! fromIntegral n

someBytes :: Int -> Int -> Gen ByteString
someBytes lo hi = do
  n <- choose (lo, hi)
  BS.pack <$> vectorOf n (choose (0, 255))

-- | An identity: none, or some bytes.
identity :: Gen (Maybe ByteString)
identity = frequency [(1, pure Nothing), (2, Just <$> someBytes 1 40)]

idsOf :: Identities -> Ids
idsOf ids = Ids {client = fromMaybe BS.empty ids.client, server = fromMaybe BS.empty ids.server}

--------------------------------------------------------------------------------
-- The OPRF

oprfSpec :: Spec
oprfSpec = do
  it "hashes an input to the same group element" $
    forM_ [0 .. 40 :: Int] $ \n -> do
      input <- generate (someBytes n (n * 7))
      Ref.hashToGroup input `shouldReturn` Just (OPRF.hashToGroup input)
  it "evaluates a blinded element under a key to the same element" $
    replicateM_' 40 $ do
      key <- randomScalar
      input <- generate (someBytes 0 80)
      let blinded = OPRF.hashToGroup input
      Ref.evaluate key blinded `shouldReturn` OPRF.blindEvaluate key blinded
  it "unblinds and finalizes an evaluated element to the same output" $
    replicateM_' 40 $ do
      key <- randomScalar
      blind <- randomScalar
      input <- generate (someBytes 0 80)
      (_, blinded) <- maybe (expectationFailure "blindWith" >> error "unreachable") pure (OPRF.blindWith blind input)
      evaluated <- maybe (expectationFailure "blindEvaluate" >> error "unreachable") pure (OPRF.blindEvaluate key blinded)
      theirs <- Ref.unblind blind evaluated >>= maybe (pure Nothing) (Ref.finalize input)
      theirs `shouldBe` OPRF.finalize input blind evaluated
      -- And both are the OPRF itself, computed without blinding.
      theirs `shouldBe` OPRF.evaluate key input
  it "expands a message to the same bytes (expand_message_xmd with SHA-512)" $
    forM_ [1, 2, 31, 32, 63, 64, 65, 127, 128, 200, 255] $ \n -> do
      message <- generate (someBytes 0 300)
      dst <- generate (someBytes 1 255)
      Ref.expandMessageXmd message dst n `shouldReturn` Just (Kdf.expandMessageXmd message dst n)

replicateM_' :: Int -> IO () -> IO ()
replicateM_' n act = forM_ [1 .. n] (const act)

--------------------------------------------------------------------------------
-- The same random values on both sides

-- | Everything one registration and one login use, chosen at random.
data Inputs = Inputs
  { password :: ByteString
  , wrongPassword :: ByteString
  , context :: ByteString
  , ids :: Identities
  , credentialId :: CredentialId
  , oprfSeed :: ByteString
  , serverKeySeed :: ByteString
  , registrationBlind :: ByteString
  , envelopeNonce :: ByteString
  , loginBlind :: ByteString
  , clientNonce :: ByteString
  , clientKeyshareSeed :: ByteString
  , maskingNonce :: ByteString
  , serverNonce :: ByteString
  , serverKeyshareSeed :: ByteString
  }

inputs :: IO Inputs
inputs = do
  password <- generate (frequency [(1, pure BS.empty), (8, someBytes 1 64), (1, someBytes 200 400)])
  wrongPassword <- generate (someBytes 65 80)
  context <- generate (frequency [(1, pure BS.empty), (3, someBytes 1 40)])
  ids <- generate (Identities <$> identity <*> identity)
  credentialId <- CredentialId <$> generate (someBytes 1 40)
  oprfSeed <- randomBytes 64
  [serverKeySeed, envelopeNonce, clientNonce, clientKeyshareSeed, maskingNonce, serverNonce, serverKeyshareSeed] <- replicateM 7 (randomBytes 32)
  registrationBlind <- randomScalar
  loginBlind <- randomScalar
  pure
    Inputs
      { password
      , wrongPassword
      , context
      , ids
      , credentialId
      , oprfSeed
      , serverKeySeed
      , registrationBlind
      , envelopeNonce
      , loginBlind
      , clientNonce
      , clientKeyshareSeed
      , maskingNonce
      , serverNonce
      , serverKeyshareSeed
      }

-- | This package's server for some inputs: its setup, and its private key
-- as libopaque takes it.
serverOf :: Inputs -> IO (ServerSetup, ByteString)
serverOf i = do
  (fakeKey, _) <- orFail "a key pair for the fake record" (deriveDiffieHellmanKeyPair i.maskingNonce)
  fake <- maybe (expectationFailure "fakeRecordWith" >> error "unreachable") pure (fakeRecordWith fakeKey i.oprfSeed)
  setup <- orFail "serverSetupWith" (serverSetupWith i.oprfSeed i.serverKeySeed fake)
  (privateKey, publicKey) <- orFail "the server's key pair" (deriveDiffieHellmanKeyPair i.serverKeySeed)
  publicKey `shouldBe` setup.serverPublicKey
  pure (setup, privateKey)

scriptedSpec :: Spec
scriptedSpec =
  forM_ [1 .. 12 :: Int] $ \n ->
    it ("gives the same bytes at every step (" <> show n <> ")") $ do
      i <- inputs
      let config = Config {context = i.context, ksf = referenceKsf}
          theirIds = idsOf i.ids
      (setup, serverPrivateKey) <- serverOf i
      key <- orFail "oprfKey" (oprfKey setup i.credentialId)

      -- Registration.
      (ourRegState, ourRequest) <- orFail "registrationRequestWith" (registrationRequestWith i.registrationBlind i.password)
      (theirRegSecret, theirRequest) <- ref "registration request" (Ref.registrationRequest (Scripted [i.registrationBlind]) i.password)
      theirRequest `sameBytes` encode ourRequest

      ourResponse <- orFail "registrationResponse" (registrationResponse setup i.credentialId ourRequest)
      (theirServerSecret, theirResponse) <- ref "registration response" (Ref.registrationResponse (Scripted [key]) theirRequest serverPrivateKey)
      theirResponse `sameBytes` encode ourResponse

      (ourRecord, ourExportKey) <- orFail "finalizeRegistrationWith" (finalizeRegistrationWith config i.envelopeNonce ourRegState ourResponse i.ids)
      (theirRecord, theirExportKey) <- ref "registration record" (Ref.finalizeRegistration (Scripted [i.envelopeNonce]) theirRegSecret theirResponse theirIds)
      theirRecord `sameBytes` encode ourRecord
      theirExportKey `sameBytes` encode ourExportKey
      theirStored <- Ref.storeRecord theirServerSecret theirRecord

      -- Login.
      (ourLoginState, ourKe1) <- orFail "clientStartWith" (clientStartWith i.loginBlind i.clientNonce i.clientKeyshareSeed i.password)
      (theirLoginSecret, theirKe1) <- ref "KE1" (Ref.clientStart (Scripted [i.loginBlind, i.clientKeyshareSeed, i.clientNonce]) i.password)
      theirKe1 `sameBytes` encode ourKe1

      let serverRandom = ServerRandom {maskingNonce = i.maskingNonce, serverNonce = i.serverNonce, keyshareSeed = i.serverKeyshareSeed}
      (ourServerState, ourKe2) <- orFail "serverRespondWith" (serverRespondWith config setup ourRecord i.credentialId serverRandom ourKe1 i.ids)
      theirs <- ref "KE2" (Ref.serverRespond (Scripted [i.maskingNonce, i.serverNonce, i.serverKeyshareSeed]) theirKe1 theirStored theirIds i.context)
      theirs.ke2 `sameBytes` encode ourKe2

      (ourKe3, ourClientKey, ourLoginExportKey) <- orFail "clientFinish" (clientFinish config ourLoginState ourKe2 i.ids)
      theirEnd <- ref "KE3" (Ref.clientFinish theirs.ke2 theirLoginSecret theirIds i.context)
      theirEnd.mac `sameBytes` encode ourKe3
      theirEnd.mac `sameBytes` theirs.expectedMac
      theirEnd.sessionKey `sameBytes` encode ourClientKey
      theirs.sessionKey `sameBytes` encode ourClientKey
      theirEnd.exportKey `sameBytes` encode ourLoginExportKey
      encode ourLoginExportKey `sameBytes` encode ourExportKey

      ourServerKey <- orFail "serverFinish" (serverFinish ourServerState ourKe3)
      encode ourServerKey `sameBytes` encode ourClientKey
      Ref.serverFinish theirs.expectedMac theirEnd.mac `shouldReturn` True

--------------------------------------------------------------------------------
-- Real random values, one side's client and the other's server

-- | Who plays the client of a registration or a login.
data Side = Ours | Theirs
  deriving stock (Eq, Show)

mixedSpec :: Spec
mixedSpec = do
  forM_ [(c, s) | c <- [Ours, Theirs], s <- [Ours, Theirs], (c, s) /= (Ours, Ours)] $ \(c, s) ->
    it ("registers and logs in: the client is " <> who c <> ", the server " <> who s) $
      replicateM_' 3 $ do
        i <- inputs
        server <- serverFor s i
        record <- register c server i
        login c server record i i.password >>= (`shouldBe` True)
        login c server record i i.wrongPassword >>= (`shouldBe` False)
  it "logs in with one side's client to a record the other side's client made" $
    forM_ [(Ours, Theirs), (Theirs, Ours)] $ \(registering, loggingIn) ->
      forM_ [Ours, Theirs] $ \s -> do
        i <- inputs
        server <- serverFor s i
        record <- register registering server i
        login loggingIn server record i i.password >>= (`shouldBe` True)
        login loggingIn server record i i.wrongPassword >>= (`shouldBe` False)
  where
    who = \case
      Ours -> "this package's"
      Theirs -> "libopaque's"

-- | A server of one side: this package's setup, or the private key
-- libopaque's server is given.
data Server
  = OurServer ServerSetup
  | TheirServer ByteString

serverFor :: Side -> Inputs -> IO Server
serverFor side i = case side of
  Ours -> OurServer <$> (orFail "generateServerSetup" =<< generateServerSetup)
  Theirs -> TheirServer . fst <$> orFail "a server key pair" (deriveDiffieHellmanKeyPair i.serverKeySeed)

-- | What a server keeps of a registration: this package's record, or
-- libopaque's stored record.
data Stored
  = OurRecord RegistrationRecord
  | TheirRecord ByteString

-- | A registration with real random values: the client of one side, with
-- the given server. Gives what the server stores.
register :: Side -> Server -> Inputs -> IO Stored
register clientSide server i = do
  let config = Config {context = i.context, ksf = referenceKsf}
  -- The client's request, and how it finishes from the response's bytes.
  (request, finish) <- case clientSide of
    Ours -> do
      (st, request) <- orFail "registrationRequest" =<< registrationRequest i.password
      pure
        ( encode request
        , \response -> do
            response' <- orFail "decoding the registration response" (decode response)
            (record, _) <- orFail "finalizeRegistration" =<< finalizeRegistration config st response' i.ids
            pure (encode record)
        )
    Theirs -> do
      (secret, request) <- ref "registration request" (Ref.registrationRequest Real i.password)
      pure (request, \response -> fst <$> ref "registration record" (Ref.finalizeRegistration Real secret response (idsOf i.ids)))
  case server of
    OurServer setup -> do
      request' <- orFail "decoding the registration request" (decode request)
      response <- orFail "registrationResponse" (registrationResponse setup i.credentialId request')
      record <- finish (encode response)
      OurRecord <$> orFail "decoding the record" (decode record)
    TheirServer privateKey -> do
      (secret, response) <- ref "registration response" (Ref.registrationResponse Real request privateKey)
      record <- finish response
      TheirRecord <$> Ref.storeRecord secret record

-- | A login with real random values: whether both sides finish, with the
-- same session key. A wrong password must fail at the client's finish.
login :: Side -> Server -> Stored -> Inputs -> ByteString -> IO Bool
login clientSide server stored i password = do
  let config = Config {context = i.context, ksf = referenceKsf}
      theirIds = idsOf i.ids
  -- KE1, and how the client finishes from KE2's bytes: KE3 and its
  -- session key, or nothing when it refuses.
  (ke1, finish) <- case clientSide of
    Ours -> do
      (st, ke1) <- orFail "clientStart" =<< clientStart password
      pure
        ( encode ke1
        , \ke2 -> do
            ke2' <- orFail "decoding KE2" (decode ke2)
            pure $ case clientFinish config st ke2' i.ids of
              Right (ke3, key, _) -> Just (encode ke3, encode key)
              Left _ -> Nothing
        )
    Theirs -> do
      (secret, ke1) <- ref "KE1" (Ref.clientStart Real password)
      pure
        ( ke1
        , \ke2 ->
            either (const Nothing) (\end -> Just (end.mac, end.sessionKey)) <$> Ref.clientFinish ke2 secret theirIds i.context
        )
  case (server, stored) of
    (OurServer setup, OurRecord record) -> do
      ke1' <- orFail "decoding KE1" (decode ke1)
      (st, ke2) <- orFail "serverRespond" =<< serverRespond config setup (Just record) i.credentialId ke1' i.ids
      finish (encode ke2) >>= \case
        Nothing -> pure False
        Just (ke3, clientKey) -> do
          ke3' <- orFail "decoding KE3" (decode ke3)
          serverKey <- orFail "serverFinish" (serverFinish st ke3')
          encode serverKey `shouldBe` clientKey
          pure True
    (TheirServer _, TheirRecord record) -> do
      answer <- ref "KE2" (Ref.serverRespond Real ke1 record theirIds i.context)
      finish answer.ke2 >>= \case
        Nothing -> pure False
        Just (ke3, clientKey) -> do
          Ref.serverFinish answer.expectedMac ke3 `shouldReturn` True
          answer.sessionKey `shouldBe` clientKey
          pure True
    _ -> expectationFailure "a record of the other side's server" >> pure False
