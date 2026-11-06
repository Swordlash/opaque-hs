-- | The cases other implementations of OPAQUE test beyond the RFC's
-- vectors (opaque-ke, bytemare/opaque, circl, opaque-ts, libopaque,
-- serenity-kit), for this package: Argon2id with the wiki's parameters,
-- messages from another session, a server key that is not the one the
-- envelope was made with, a reflected OPRF element, validation on decoding,
-- the bounds of the two-byte lengths, zero scalars, identities, the server's
-- key material, and a record frozen with this version that every later one
-- must still accept.
module Test.Hardening (spec) where

import Crypto.OPAQUE.Internal
import Crypto.OPAQUE.Kdf (hkdfExpand)
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Sodium (argon2id, scalarMultBase)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Char (digitToInt)
import Data.Either (isLeft)
import Test.Hspec

-- | The wiki's Argon2id: 128 MiB, four passes.
wikiKsf :: Ksf
wikiKsf = Argon2id {opsLimit = 4, memLimit = 128 * 1024 * 1024}

-- | A quick Argon2id, libsodium's least, for the cases about something
-- else.
quick :: Config
quick = Config {context = "opaque-test", ksf = Argon2id {opsLimit = 1, memLimit = 8192}}

unhex :: ByteString -> ByteString
unhex h
  | BS.length h < 2 = BS.empty
  | otherwise = BS.cons (digit 0 * 16 + digit 1) (unhex (BS.drop 2 h))
  where
    digit i = fromIntegral (digitToInt (toEnum (fromIntegral (BS.index h i))))

-- | A scalar of one repeated byte, the top byte zero (below the order).
scalar :: Word -> ByteString
scalar b = BS.replicate 31 (fromIntegral b) <> BS.singleton 0

ok :: (Show e) => Either e a -> IO a
ok = either (\e -> expectationFailure (show e) >> error "unreachable") pure

-- | A setup made of fixed seeds.
setupOf :: Word -> ServerSetup
setupOf b = either (error . show) id $ do
  fake <- maybe (Left DeriveKeyPairError) Right (fakeRecordWith (scalar (b + 1)) (BS.replicate 64 (fromIntegral b)))
  serverSetupWith (BS.replicate 64 (fromIntegral (b + 2))) (BS.replicate 32 (fromIntegral (b + 3))) fake

cid :: CredentialId
cid = CredentialId "user-1"

-- | Register a password with fixed random values.
registered :: Config -> ServerSetup -> Identities -> ByteString -> Either Error (RegistrationRecord, ExportKey)
registered config setup ids password = do
  (st, request) <- registrationRequestWith (scalar 31) password
  response <- registrationResponse setup cid request
  finalizeRegistrationWith config (BS.replicate 32 32) st response ids

random1 :: ServerRandom
random1 = ServerRandom {maskingNonce = BS.replicate 32 41, serverNonce = BS.replicate 32 42, keyshareSeed = BS.replicate 32 43}

-- | A login with fixed random values (the seed byte chooses the client's),
-- up to the client's finish.
loginWith :: Config -> ServerSetup -> RegistrationRecord -> Identities -> Identities -> Word -> ByteString -> Either Error ((ServerLoginState, KE2), Either Error (KE3, SessionKey, ExportKey))
loginWith config setup record serverIds clientIds b password = do
  (cst, ke1) <- clientStartWith (scalar b) (BS.replicate 32 (fromIntegral b)) (BS.replicate 32 (fromIntegral (b + 1))) password
  (sst, ke2) <- serverRespondWith config setup record cid random1 ke1 serverIds
  pure ((sst, ke2), clientFinish config cst ke2 clientIds)

spec :: Spec
spec = do
  describe "Argon2id" $ do
    it "stretches with the wiki's parameters as another implementation does (Node 24's crypto.argon2Sync, OpenSSL's)" $
      argon2id 4 (128 * 1024 * 1024) (BS.replicate 16 0) (BS.pack [0 .. 63])
        `shouldBe` Just (unhex "5690fdc5a537a36a9923ca99fd385a9cae97ba2f56ae8615ae1ff9fcef8efbaa39dbf9ab34642df7b0e2ad670a86436f5a18e69af373b2e39085cef7ded420ea")
    it "stretches with libsodium's least parameters as another implementation does" $
      argon2id 1 8192 (BS.replicate 16 0) (BS.pack [0 .. 63])
        `shouldBe` Just (unhex "d57e96a0e76960a08d51b88fc0aab6e0bbb055d82626904333cf8163a06c36de278f8cf3f15d0a6e7752dcca01ef89b635e6f86618b77299da33ba4dbdd1b35c")
    it "registers and logs in with the wiki's parameters" $ do
      let config = Config {context = "wiki OPAQUE v1", ksf = wikiKsf}
          setup = setupOf 1
      (record, ExportKey exported) <- ok (registered config setup defaultIdentities "a password")
      ((sst, _), finished) <- ok (loginWith config setup record defaultIdentities defaultIdentities 5 "a password")
      (ke3, SessionKey k, ExportKey exported') <- ok finished
      SessionKey k' <- ok (serverFinish sst ke3)
      (k, exported') `shouldBe` (k', exported)
      -- A record made with no stretching does not open with it.
      (identityRecord, _) <- ok (registered config {ksf = Identity} setup defaultIdentities "a password")
      ((_, _), wrong) <- ok (loginWith config setup identityRecord defaultIdentities defaultIdentities 5 "a password")
      fmap (const ()) wrong `shouldBe` Left EnvelopeRecoveryError

  describe "another session's message" $ do
    let setup = setupOf 2
    it "is refused: a KE2 made for another KE1, and a KE3 for another server state" $ do
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      (cstA, _) <- ok (clientStartWith (scalar 51) (BS.replicate 32 52) (BS.replicate 32 53) "pw")
      (_, ke1B) <- ok (clientStartWith (scalar 54) (BS.replicate 32 55) (BS.replicate 32 56) "pw")
      (sstB, ke2B) <- ok (serverRespondWith quick setup record cid random1 ke1B defaultIdentities)
      fmap (const ()) (clientFinish quick cstA ke2B defaultIdentities) `shouldSatisfy` isLeft
      -- A KE3 of a finished session A, checked by session B's server.
      ((_, _), finishedA) <- ok (loginWith quick setup record defaultIdentities defaultIdentities 61 "pw")
      (ke3A, _, _) <- ok finishedA
      fmap (const ()) (serverFinish sstB ke3A) `shouldBe` Left ClientAuthenticationError

  describe "the server's public key in the masked response" $ do
    let setup = setupOf 3
    it "must be the one the envelope was made with: another valid key, and a key that is no element, are refused" $ do
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      (cst, ke1) <- ok (clientStartWith (scalar 71) (BS.replicate 32 72) (BS.replicate 32 73) "pw")
      (_, ke2) <- ok (serverRespondWith quick setup record cid random1 ke1 defaultIdentities)
      other <- maybe (expectationFailure "no key" >> error "unreachable") pure (scalarMultBase (scalar 74))
      let remasked pk =
            let cr = ke2.credentialResponse
                pad = hkdfExpand record.maskingKey (cr.maskingNonce <> "CredentialResponsePad") (32 + 32 + 64)
                plain = pk <> record.envelope.nonce <> record.envelope.authTag
             in ke2 {credentialResponse = cr {maskedResponse = BS.pack (BS.zipWith xor pad plain)}}
      -- The re-masking itself is right: the real key still opens.
      fmap (const ()) (clientFinish quick cst (remasked setup.serverPublicKey) defaultIdentities) `shouldBe` Right ()
      fmap (const ()) (clientFinish quick cst (remasked other) defaultIdentities) `shouldBe` Left EnvelopeRecoveryError
      fmap (const ()) (clientFinish quick cst (remasked (BS.replicate 32 0xff)) defaultIdentities) `shouldBe` Left EnvelopeRecoveryError

  describe "a reflected OPRF element" $ do
    let setup = setupOf 4
    it "is refused at registration" $ do
      (st, request) <- ok (registrationRequestWith (scalar 81) "pw")
      let reflected = RegistrationResponse {evaluatedMessage = request.blindedMessage, serverPublicKey = setup.serverPublicKey}
      fmap (const ()) (finalizeRegistrationWith quick (BS.replicate 32 1) st reflected defaultIdentities) `shouldBe` Left ReflectedValueError
    it "is refused at login" $ do
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      (cst, ke1) <- ok (clientStartWith (scalar 82) (BS.replicate 32 83) (BS.replicate 32 84) "pw")
      (_, ke2) <- ok (serverRespondWith quick setup record cid random1 ke1 defaultIdentities)
      let cr = ke2.credentialResponse
          reflected = ke2 {credentialResponse = CredentialResponse {evaluatedMessage = ke1.blindedMessage, maskingNonce = cr.maskingNonce, maskedResponse = cr.maskedResponse}}
      fmap (const ()) (clientFinish quick cst reflected defaultIdentities) `shouldBe` Left ReflectedValueError

  describe "decoding" $ do
    let setup = setupOf 5
        -- An encoding of the field's prime itself, and of 1, which is
        -- "negative" in ristretto255's sense: neither is canonical.
        nonCanonical = [unhex "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", BS.singleton 1 <> BS.replicate 31 0]
    it "refuses a record with a client public key that is not a canonical element, or fields of the wrong length" $ do
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      let bytes = encode record
          withKey k = k <> BS.drop 32 bytes
      fmap (const ()) (decode bytes :: Either Error RegistrationRecord) `shouldBe` Right ()
      mapM_ (\k -> fmap (const ()) (decode (withKey k) :: Either Error RegistrationRecord) `shouldBe` Left DeserializeError) (BS.replicate 32 0 : nonCanonical)
      -- A masking key or an envelope a byte short or long.
      mapM_ (\b -> fmap (const ()) (decode b :: Either Error RegistrationRecord) `shouldBe` Left DeserializeError) [BS.init bytes, bytes <> "x"]
    it "refuses a KE1 whose elements are not canonical, and a KE2 likewise" $ do
      (_, ke1) <- ok (clientStartWith (scalar 91) (BS.replicate 32 92) (BS.replicate 32 93) "pw")
      let bytes = encode ke1
      mapM_ (\e -> fmap (const ()) (decode (e <> BS.drop 32 bytes) :: Either Error KE1) `shouldBe` Left DeserializeError) nonCanonical
      mapM_ (\e -> fmap (const ()) (decode (BS.take 64 bytes <> e) :: Either Error KE1) `shouldBe` Left DeserializeError) nonCanonical
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      (_, ke2) <- ok (serverRespondWith quick setup record cid random1 ke1 defaultIdentities)
      let ke2bytes = encode ke2
      mapM_ (\e -> fmap (const ()) (decode (e <> BS.drop 32 ke2bytes) :: Either Error KE2) `shouldBe` Left DeserializeError) nonCanonical

  describe "the two-byte lengths" $ do
    let setup = setupOf 6
    it "take a password of 65534 bytes, through a whole login, and refuse one of 65535 (RFC 9497, 5.1)" $ do
      let long = BS.replicate 65534 0x61
      (record, _) <- ok (registered quick setup defaultIdentities long)
      ((sst, _), finished) <- ok (loginWith quick setup record defaultIdentities defaultIdentities 7 long)
      (ke3, _, _) <- ok finished
      fmap (const ()) (serverFinish sst ke3) `shouldBe` Right ()
      fmap (const ()) (registrationRequestWith (scalar 1) (BS.replicate 65535 0x61)) `shouldBe` Left InvalidInputError
      fmap (const ()) (clientStartWith (scalar 1) (BS.replicate 32 1) (BS.replicate 32 2) (BS.replicate 65535 0x61)) `shouldBe` Left InvalidInputError
    it "take an OPRF input of 65534 bytes and refuse one of 65535" $ do
      let k = scalar 3
      fmap (const ()) (OPRF.evaluate k (BS.replicate 65534 0)) `shouldBe` Just ()
      OPRF.evaluate k (BS.replicate 65535 0) `shouldBe` Nothing
      OPRF.blindWith (scalar 4) (BS.replicate 65535 0) `shouldBe` Nothing
    it "take an identity and a context of 65535 bytes, and refuse 65536" $ do
      let big n = BS.replicate n 0x62
          ids n = Identities {client = Just (big n), server = Just (big n)}
          config n = quick {context = big n}
      (record, _) <- ok (registered quick setup (ids 65535) "pw")
      ((_, _), finished) <- ok (loginWith (config 65535) setup record (ids 65535) (ids 65535) 7 "pw")
      fmap (const ()) finished `shouldBe` Right ()
      fmap (const ()) (registered quick setup (ids 65536) "pw") `shouldBe` Left InvalidInputError
      fmap (const ()) (loginWith (config 65536) setup record (ids 65535) (ids 65535) 7 "pw") `shouldBe` Left InvalidInputError
      fmap (const ()) (loginWith quick setup record (ids 65536) defaultIdentities 7 "pw") `shouldBe` Left InvalidInputError

  describe "zero scalars" $
    it "are never used: a zero blind, a zero fake record key and a zero server key are refused, and a zero seed gives a key that is not zero" $ do
      let zero = BS.replicate 32 0
      fmap (const ()) (registrationRequestWith zero "pw") `shouldBe` Left InvalidInputError
      fmap (const ()) (clientStartWith zero (BS.replicate 32 1) (BS.replicate 32 2) "pw") `shouldBe` Left InvalidInputError
      OPRF.finalize "pw" zero (setupOf 7).serverPublicKey `shouldBe` Nothing
      -- A blind a byte short is refused before libsodium reads it.
      OPRF.finalize "pw" (BS.drop 1 (scalar 5)) (setupOf 7).serverPublicKey `shouldBe` Nothing
      fmap (const ()) (fakeRecordWith zero (BS.replicate 64 1)) `shouldBe` Nothing
      -- A key pair from a seed of zeros is a key pair: the seed is hashed.
      (sk, _) <- ok (deriveDiffieHellmanKeyPair zero)
      sk `shouldNotBe` zero

  describe "identities" $ do
    let setup = setupOf 8
    it "work empty, with an empty password, through the whole flow" $ do
      (record, ExportKey exported) <- ok (registered quick setup defaultIdentities "")
      ((sst, _), finished) <- ok (loginWith quick setup record defaultIdentities defaultIdentities 9 "")
      (ke3, _, ExportKey exported') <- ok finished
      exported' `shouldBe` exported
      fmap (const ()) (serverFinish sst ke3) `shouldBe` Right ()
    it "left out are the parties' public keys: the same messages and keys as when given" $ do
      (record, _) <- ok (registered quick setup defaultIdentities "pw")
      let explicit = Identities {client = Just record.clientPublicKey, server = Just setup.serverPublicKey}
      ((_, ke2a), finishedA) <- ok (loginWith quick setup record defaultIdentities defaultIdentities 10 "pw")
      ((_, ke2b), finishedB) <- ok (loginWith quick setup record explicit explicit 10 "pw")
      encode ke2a `shouldBe` encode ke2b
      (ke3a, SessionKey ka, _) <- ok finishedA
      (ke3b, SessionKey kb, _) <- ok finishedB
      (encode ke3a, ka) `shouldBe` (encode ke3b, kb)
      -- And a registration with them given is the same record.
      (record', _) <- ok (registered quick setup explicit "pw")
      encode record' `shouldBe` encode record

  describe "the server's key material" $
    it "is refused with a zero private key, a public key that is not its own, or a seed of the wrong length" $ do
      let bytes = encode (setupOf 9)
          (seed, rest) = BS.splitAt 64 bytes
          (sk, rest') = BS.splitAt 32 rest
          (pk, fake) = BS.splitAt 32 rest'
          refused b = fmap (const ()) (decode b :: Either Error ServerSetup) `shouldBe` Left DeserializeError
      fmap (const ()) (decode bytes :: Either Error ServerSetup) `shouldBe` Right ()
      refused (seed <> BS.replicate 32 0 <> pk <> fake)
      refused (seed <> sk <> (setupOf 10).serverPublicKey <> fake)
      refused (BS.drop 1 seed <> sk <> pk <> fake)
      refused (seed <> "x" <> sk <> pk <> fake)

  describe "a record frozen with the first version" $
    it "still logs in, with the wiki's Argon2id, and is still what the same inputs make" $ do
      let config = Config {context = "wiki OPAQUE v1", ksf = wikiKsf}
      setup <- ok (decode frozenSetup)
      record <- ok (decode frozenRecord)
      -- The same inputs make the same bytes: an encoding or a derivation
      -- that changed would change them.
      encode frozenSetupMade `shouldBe` frozenSetup
      madeRecord <- ok $ do
        (st, request) <- registrationRequestWith (scalar 25) "a frozen password"
        response <- registrationResponse frozenSetupMade (CredentialId "frozen-user") request
        finalizeRegistrationWith config (BS.replicate 32 26) st response defaultIdentities
      encode (fst madeRecord) `shouldBe` frozenRecord
      (cst, ke1) <- ok (clientStartWith (scalar 27) (BS.replicate 32 28) (BS.replicate 32 29) "a frozen password")
      (sst, ke2) <- ok (serverRespondWith config setup record (CredentialId "frozen-user") random1 ke1 defaultIdentities)
      (ke3, _, ExportKey exported) <- ok (clientFinish config cst ke2 defaultIdentities)
      encode (ExportKey exported) `shouldBe` frozenExport
      fmap (const ()) (serverFinish sst ke3) `shouldBe` Right ()
  where
    frozenSetupMade = either (error . show) id $ do
      fake <- maybe (Left DeriveKeyPairError) Right (fakeRecordWith (scalar 21) (BS.replicate 64 22))
      serverSetupWith (BS.replicate 64 23) (BS.replicate 32 24) fake

-- | The frozen server setup, record and export key: made by this version
-- (WP5.74a) from fixed seeds, with the password "a frozen password", the
-- credential id "frozen-user", the context "wiki OPAQUE v1" and Argon2id
-- with 128 MiB and four passes.
frozenSetup, frozenRecord, frozenExport :: ByteString
frozenSetup =
  unhex $
    "1717171717171717171717171717171717171717171717171717171717171717"
      <> "1717171717171717171717171717171717171717171717171717171717171717"
      <> "13244c7320d250130e9c482edd2d189b96f430bd8937205dedaa7e1b226bef0e"
      <> "1ac3937450a85163df15b81f31483efb4b5612112fd46ae70cc94c8a849b7b37"
      <> "e661fb5f8a60d01830e69f3726acc76f24cea7b503dd5c3c98e31671010a4d4e"
      <> "1616161616161616161616161616161616161616161616161616161616161616"
      <> "1616161616161616161616161616161616161616161616161616161616161616"
      <> "0000000000000000000000000000000000000000000000000000000000000000"
      <> "0000000000000000000000000000000000000000000000000000000000000000"
      <> "0000000000000000000000000000000000000000000000000000000000000000"
frozenRecord =
  unhex $
    "7cc19a54f23fa9476ddb60767df173129026eeb09798946423e5b05deed1672e"
      <> "e362cd1d1752e5bf707164fe2f43860e66d2b0c1079df15c515ac43e05925833"
      <> "c039d8a693577c5415296165d203be5017f4c1cdb9cf6d0602ed3d77cd7518c6"
      <> "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
      <> "51515d3246683625f231fdedaef3a5c5c95850605d1136340a7e0006d709eeea"
      <> "297a41ed0c3ee219a322081e711901ee44334682c4b831791f43a8f2571552c1"
frozenExport = unhex "7b8193e1574ba5f98051b392741daa1cd30eec149d967c0352330168bdcb2935630916d9f15560578ab15bd381ee17b013f64d95c6d7bceb22b6114a68fa0949"
