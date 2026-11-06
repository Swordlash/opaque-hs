-- | Registrations and logins with real random values: a right password logs
-- in, a wrong one fails at the client's finish, tampered messages fail, and
-- a login for a client with no record answers in the same shape as one with
-- a record.
module Test.RoundTrip (spec) where

import Crypto.OPAQUE
import Data.Bits (complementBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Test.Hspec

-- | Argon2id with libsodium's smallest limits, so that the tests are quick
-- and still go through the real stretch.
config :: Config
config = Config {context = "opaque-test", ksf = Argon2id {opsLimit = 1, memLimit = 8192}}

cid :: CredentialId
cid = CredentialId "user-1"

orFail :: (Show e) => Either e a -> IO a
orFail = either (\e -> expectationFailure (show e) >> error "unreachable") pure

-- | Register a password and give the setup, the record and the export key.
register :: ByteString -> IO (ServerSetup, RegistrationRecord, ExportKey)
register password = do
  setup <- orFail =<< generateServerSetup
  (st, request) <- orFail =<< registrationRequest password
  response <- orFail (registrationResponse setup cid request)
  (record, exportKey) <- orFail =<< finalizeRegistration config st response defaultIdentities
  pure (setup, record, exportKey)

-- | Run a login up to KE2, through the messages' encodings.
startLogin :: ServerSetup -> Maybe RegistrationRecord -> ByteString -> IO (ClientLoginState, ServerLoginState, ByteString)
startLogin setup record password = do
  (cst, ke1) <- orFail =<< clientStart password
  ke1' <- orFail (decode (encode ke1))
  (sst, ke2) <- orFail =<< serverRespond config setup record cid ke1' defaultIdentities
  pure (cst, sst, encode ke2)

-- | Flip one bit of the byte at the index.
flipAt :: Int -> ByteString -> ByteString
flipAt i bs = BS.take i bs <> BS.singleton (complementBit (BS.index bs i) 0) <> BS.drop (i + 1) bs

finish :: ClientLoginState -> ByteString -> Either Error (KE3, SessionKey, ExportKey)
finish cst ke2 = decode ke2 >>= \k -> clientFinish config cst k defaultIdentities

spec :: Spec
spec = do
  describe "a login" $ do
    it "with the right password agrees on a session key and the export key" $ do
      (setup, record, exportKey) <- register "correct horse"
      (cst, sst, ke2) <- startLogin setup (Just record) "correct horse"
      (ke3, clientKey, exportKey') <- orFail (finish cst ke2)
      serverKey <- orFail (decode (encode ke3) >>= serverFinish sst)
      encode serverKey `shouldBe` encode clientKey
      encode exportKey' `shouldBe` encode exportKey
      BS.length (encode clientKey) `shouldBe` 64
    it "with a wrong password fails at the client's finish" $ do
      (setup, record, _) <- register "correct horse"
      (cst, _, ke2) <- startLogin setup (Just record) "battery staple"
      fmap (const ()) (finish cst ke2) `shouldBe` Left EnvelopeRecoveryError
    it "with the record read back from its encoding logs in" $ do
      (setup, record, _) <- register "pw"
      record' <- orFail (decode (encode record))
      setup' <- orFail (decode (encode setup))
      (cst, _, ke2) <- startLogin setup' (Just record') "pw"
      fmap (const ()) (finish cst ke2) `shouldBe` Right ()
    it "with another context fails" $ do
      (setup, record, _) <- register "pw"
      (cst, _, ke2) <- startLogin setup (Just record) "pw"
      let other = config {context = "another application"}
      fmap (const ()) (decode ke2 >>= \k -> clientFinish other cst k defaultIdentities)
        `shouldBe` Left ServerAuthenticationError
    it "with another key stretching function fails" $ do
      (setup, record, _) <- register "pw"
      (cst, _, ke2) <- startLogin setup (Just record) "pw"
      let other = config {ksf = Identity}
      fmap (const ()) (decode ke2 >>= \k -> clientFinish other cst k defaultIdentities)
        `shouldBe` Left EnvelopeRecoveryError
    it "with other identities fails" $ do
      (setup, record, _) <- register "pw"
      (cst, _, ke2) <- startLogin setup (Just record) "pw"
      let ids = defaultIdentities {client = Just "alice"}
      fmap (const ()) (decode ke2 >>= \k -> clientFinish config cst k ids)
        `shouldBe` Left EnvelopeRecoveryError
    it "fails when any byte of KE2 is changed" $ do
      (setup, record, _) <- register "pw"
      (cst, _, ke2) <- startLogin setup (Just record) "pw"
      -- One byte in each field: the evaluated element, the masking nonce,
      -- the masked response, the server's nonce, its key share and its MAC.
      let tampered = [flipAt i ke2 | i <- [0, 40, 100, 200, 230, 300]]
      mapM_ (\t -> either (const True) (const False) (finish cst t) `shouldBe` True) tampered
    it "is refused by the server when KE3 is changed" $ do
      (setup, record, _) <- register "pw"
      (cst, sst, ke2) <- startLogin setup (Just record) "pw"
      (ke3, _, _) <- orFail (finish cst ke2)
      fmap (const ()) (decode (flipAt 10 (encode ke3)) >>= serverFinish sst)
        `shouldBe` Left ClientAuthenticationError
  describe "a login for a client with no record" $ do
    it "answers with a KE2 of the same shape" $ do
      (setup, record, _) <- register "pw"
      (_, _, real) <- startLogin setup (Just record) "pw"
      (cst, _, fake) <- startLogin setup Nothing "pw"
      BS.length fake `shouldBe` BS.length real
      fmap (const ()) (decode fake :: Either Error KE2) `shouldBe` Right ()
      fmap (const ()) (finish cst fake) `shouldBe` Left EnvelopeRecoveryError
    it "answers differently each time, as a real record does" $ do
      (setup, _, _) <- register "pw"
      (_, _, a) <- startLogin setup Nothing "pw"
      (_, _, b) <- startLogin setup Nothing "pw"
      a `shouldNotBe` b
  describe "the encodings" $ do
    it "refuse the identity element" $
      fmap (const ()) (decode (BS.replicate 32 0) :: Either Error RegistrationRequest)
        `shouldBe` Left DeserializeError
    it "refuse a message of the wrong length" $
      fmap (const ()) (decode (BS.replicate 95 1) :: Either Error KE1)
        `shouldBe` Left DeserializeError
    it "keep a client's login state" $ do
      (setup, record, _) <- register "pw"
      (cst, ke1) <- orFail =<< clientStart "pw"
      cst' <- orFail (decode (encode cst))
      (_, ke2) <- orFail =<< serverRespond config setup (Just record) cid ke1 defaultIdentities
      fmap (const ()) (clientFinish config cst' ke2 defaultIdentities) `shouldBe` Right ()
  describe "a password" $
    it "of 65536 bytes or more is refused, and one of 65535 is taken" $ do
      r <- registrationRequest (BS.replicate 65536 0x61)
      fmap (const ()) r `shouldBe` Left InvalidInputError
      taken <- registrationRequest (BS.replicate 65535 0x61)
      fmap (const ()) taken `shouldBe` Right ()
