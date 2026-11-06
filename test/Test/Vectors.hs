-- | The test vectors of RFC 9807 (appendix C) and RFC 9497 (appendix A.1.1)
-- for the suite this package implements, ristretto255 with SHA-512, copied
-- from the RFCs' texts. OPAQUE's real vectors 3 and 4 use Curve25519 for the
-- key exchange, vectors 5 and 6 and fake vectors 2 and 3 use other groups:
-- they are for suites this package does not implement.
--
-- Every vector runs with the identity as its key stretching function, as
-- the RFC's do, and every value its random inputs would take is given.
module Test.Vectors (spec) where

import Crypto.OPAQUE.Internal
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Sodium (scalarMultBase)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Maybe (fromMaybe)
import Test.Hspec

-- | A vector: each value's name in the RFC, and its bytes in hexadecimal.
type Vector = [(String, ByteString)]

-- | The value a vector names, decoded from hexadecimal. A name that is not
-- in the vector is a mistake in the test, and stops it.
at :: Vector -> String -> ByteString
at v name = unhex (fromMaybe (error ("no " <> name <> " in the vector")) (lookup name v))
  where
    unhex hex
      | BS.null hex = BS.empty
      | BS.length hex >= 2 && BS.all (isHexDigit . toEnum . fromIntegral) (BS.take 2 hex) =
          let digit i = fromIntegral (digitToInt (toEnum (fromIntegral (BS.index hex i))))
           in BS.cons (digit 0 * 16 + digit 1) (unhex (BS.drop 2 hex))
      | otherwise = error ("bad hex for " <> name)

-- | Whether a vector names a value.
has :: Vector -> String -> Bool
has v name = maybe False (const True) (lookup name v)

spec :: Spec
spec = do
  describe "RFC 9497 OPRF(ristretto255, SHA-512), modeOPRF" $ do
    let seed = at oprfKeys "Seed"
        sk = at oprfKeys "skSm"
    it "derives the server's key from the seed and the key info" $
      fmap fst (OPRF.deriveKeyPair seed (at oprfKeys "KeyInfo")) `shouldBe` Just sk
    mapM_ (oprfVector sk) [("test vector 1", oprf1), ("test vector 2", oprf2)]
  describe "RFC 9807 OPAQUE-3DH real test vector 1 (no identities)" $
    realVector real1
  describe "RFC 9807 OPAQUE-3DH real test vector 2 (identities alice and bob)" $
    realVector real2
  describe "RFC 9807 OPAQUE-3DH fake test vector 1" $
    fakeVector fake1

-- | One OPRF vector: Blind with the given blind, BlindEvaluate with the
-- server's key, Finalize, and Evaluate.
oprfVector :: ByteString -> (String, Vector) -> Spec
oprfVector sk (name, v) = describe name $ do
  let input = at v "Input"
      blinded = OPRF.blindWith (at v "Blind") input
  it "blinds the input" $
    fmap snd blinded `shouldBe` Just (at v "BlindedElement")
  it "evaluates the blinded element" $
    (OPRF.blindEvaluate sk . snd =<< blinded) `shouldBe` Just (at v "EvaluationElement")
  it "finalizes to the output" $
    OPRF.finalize input (at v "Blind") (at v "EvaluationElement") `shouldBe` Just (at v "Output")
  it "evaluates to the same output with the key and the input" $
    OPRF.evaluate sk input `shouldBe` Just (at v "Output")

-- | The configuration of every vector: its context, and no stretching.
configOf :: Vector -> Config
configOf v = Config {context = at v "Context", ksf = Identity}

-- | The identities a vector gives, if any.
identitiesOf :: Vector -> Identities
identitiesOf v =
  Identities
    { client = if has v "client_identity" then Just (at v "client_identity") else Nothing
    , server = if has v "server_identity" then Just (at v "server_identity") else Nothing
    }

-- | A setup with the vector's OPRF seed and key pair. The fake record is
-- given separately where a vector uses one.
setupOf :: Vector -> RegistrationRecord -> ServerSetup
setupOf v fake =
  ServerSetup
    { oprfSeed = at v "oprf_seed"
    , serverPrivateKey = at v "server_private_key"
    , serverPublicKey = at v "server_public_key"
    , fakeRecord = fake
    }

serverRandomOf :: Vector -> ServerRandom
serverRandomOf v =
  ServerRandom
    { maskingNonce = at v "masking_nonce"
    , serverNonce = at v "server_nonce"
    , keyshareSeed = at v "server_keyshare_seed"
    }

-- | Fail with the error, or give the value.
orFail :: (Show e) => Either e a -> IO a
orFail = either (\e -> expectationFailure (show e) >> error "unreachable") pure

-- | A real vector: registration, then a login, each message compared with
-- the RFC's bytes, and the keys both sides end with.
realVector :: Vector -> Spec
realVector v = do
  let config = configOf v
      ids = identitiesOf v
      cid = CredentialId (at v "credential_identifier")
      password = at v "password"
      setup = setupOf v unusedFake
      unusedFake = RegistrationRecord "" "" (Envelope "" "")
  it "has the server's public key of its private key" $
    scalarMultBase (at v "server_private_key") `shouldBe` Just (at v "server_public_key")
  it "derives the client's OPRF key" $
    oprfKey setup cid `shouldBe` Right (at v "oprf_key")
  it "registers" $ do
    (st, request) <- orFail (registrationRequestWith (at v "blind_registration") password)
    encode request `shouldBe` at v "registration_request"
    response <- orFail (registrationResponse setup cid request)
    encode response `shouldBe` at v "registration_response"
    (record, exportKey) <- orFail (finalizeRegistrationWith config (at v "envelope_nonce") st response ids)
    encode record `shouldBe` at v "registration_upload"
    encode exportKey `shouldBe` at v "export_key"
    (record.envelope.nonce <> record.envelope.authTag) `shouldBe` at v "envelope"
    record.clientPublicKey `shouldBe` at v "client_public_key"
  it "stretches the OPRF output into the randomized password" $ do
    (st, request) <- orFail (registrationRequestWith (at v "blind_registration") password)
    response <- orFail (registrationResponse setup cid request)
    let output = OPRF.finalize password st.blind response.evaluatedMessage
    fmap (randomizedPassword Identity) output `shouldBe` Just (Right (at v "randomized_password"))
  it "logs in" $ do
    record <- orFail (decode (at v "registration_upload"))
    (cst, ke1) <- orFail (clientStartWith (at v "blind_login") (at v "client_nonce") (at v "client_keyshare_seed") password)
    encode ke1 `shouldBe` at v "KE1"
    ke1' <- orFail (decode (encode ke1))
    (sst, ke2) <- orFail (serverRespondWith config setup record cid (serverRandomOf v) ke1' ids)
    encode ke2 `shouldBe` at v "KE2"
    ke2' <- orFail (decode (encode ke2))
    (ke3, sessionKey, exportKey) <- orFail (clientFinish config cst ke2' ids)
    encode ke3 `shouldBe` at v "KE3"
    encode sessionKey `shouldBe` at v "session_key"
    encode exportKey `shouldBe` at v "export_key"
    ke3' <- orFail (decode (encode ke3))
    serverKey <- orFail (serverFinish sst ke3')
    encode serverKey `shouldBe` at v "session_key"

-- | A fake vector: the server answers a KE1 for a client with no record,
-- with the vector's fake record, and its KE2 is the RFC's.
fakeVector :: Vector -> Spec
fakeVector v = do
  let config = configOf v
      ids = identitiesOf v
      cid = CredentialId (at v "credential_identifier")
  it "answers with the fake record" $ do
    fake <- maybe (expectationFailure "no fake record" >> error "unreachable") pure (fakeRecordWith (at v "client_private_key") (at v "masking_key"))
    fake.clientPublicKey `shouldBe` at v "client_public_key"
    let setup = setupOf v fake
    ke1 <- orFail (decode (at v "KE1"))
    (_, ke2) <- orFail (serverRespondWith config setup setup.fakeRecord cid (serverRandomOf v) ke1 ids)
    encode ke2 `shouldBe` at v "KE2"

-- | RFC 9497, appendix A.1.1: the server's key for the OPRF mode's vectors.
oprfKeys :: Vector
oprfKeys =
  [ ("Seed", "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
  , ("KeyInfo", "74657374206b6579")
  , ("skSm", "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
  ]

-- | RFC 9497, appendix A.1.1.1.
oprf1 :: Vector
oprf1 =
  [ ("Input", "00")
  , ("Blind", "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")
  , ("BlindedElement", "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c")
  , ("EvaluationElement", "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e")
  , ("Output", "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3" <> "ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
  ]

-- | RFC 9497, appendix A.1.1.2.
oprf2 :: Vector
oprf2 =
  [ ("Input", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
  , ("Blind", "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")
  , ("BlindedElement", "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418")
  , ("EvaluationElement", "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25")
  , ("Output", "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4" <> "f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73")
  ]

-- | RFC 9807, appendix C.1.1: OPAQUE-3DH real test vector 1.
real1 :: Vector
real1 =
  [ ("Context", "4f50415155452d504f43")
  , ("oprf_seed", "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fd" <> "c65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef")
  , ("credential_identifier", "31323334")
  , ("password", "436f7272656374486f72736542617474657279537461706c65")
  , ("envelope_nonce", "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec")
  , ("masking_nonce", "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d")
  , ("server_private_key", "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d")
  , ("server_public_key", "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78")
  , ("server_nonce", "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1")
  , ("client_nonce", "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc")
  , ("client_keyshare_seed", "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b")
  , ("server_keyshare_seed", "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f")
  , ("blind_registration", "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01")
  , ("blind_login", "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308")
  , ("client_public_key", "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675")
  , ("auth_key", "6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494f" <> "c555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822")
  , ("randomized_password", "aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adee" <> "a73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9")
  , ("envelope", "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec" <> "634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b" <> "8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5")
  , ("handshake_secret", "81263cb85a0cfa12450f0f388de4e92291ec4c7c7a0878b624550ff528726332" <> "f1298fc6cc822a432c89504347c7a2ccd70316ae3da6a15e0399e6db3f7c1b12")
  , ("server_mac_key", "0d36b26cfe38f51f804f0a9361818f32ee1ce2a4e5578653b527184af058d3b2" <> "d8075c296fd84d24677913d1baa109290cd81a13ed383f9091a3804e65298dfc")
  , ("client_mac_key", "91750adbac54a5e8e53b4c233cc8d369fe83b0de1b6a3cd85575eeb0bb01a6a9" <> "0a086a2cf5fe75fff2a9379c30ba9049510a33b5b0b1444a88800fc3eee2260d")
  , ("oprf_key", "5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05")
  , ("registration_request", "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71")
  , ("registration_response", "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019" <> "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78")
  , ("registration_upload", "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675" <> "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb958" <> "64eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5" <> "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec" <> "634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b" <> "8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5")
  , ("KE1", "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d" <> "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc" <> "6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326")
  , ("KE2", "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471" <> "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d" <> "d6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146" <> "a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe" <> "dc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c" <> "6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b6" <> "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1" <> "c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a" <> "660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a" <> "162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90")
  , ("KE3", "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2" <> "661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442")
  , ("export_key", "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62" <> "950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16")
  , ("session_key", "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc67" <> "31fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f")
  ]

-- | RFC 9807, appendix C.1.2: OPAQUE-3DH real test vector 2.
real2 :: Vector
real2 =
  [ ("Context", "4f50415155452d504f43")
  , ("client_identity", "616c696365")
  , ("server_identity", "626f62")
  , ("oprf_seed", "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fd" <> "c65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef")
  , ("credential_identifier", "31323334")
  , ("password", "436f7272656374486f72736542617474657279537461706c65")
  , ("envelope_nonce", "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec")
  , ("masking_nonce", "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d")
  , ("server_private_key", "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d")
  , ("server_public_key", "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78")
  , ("server_nonce", "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1")
  , ("client_nonce", "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc")
  , ("client_keyshare_seed", "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b")
  , ("server_keyshare_seed", "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f")
  , ("blind_registration", "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01")
  , ("blind_login", "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308")
  , ("client_public_key", "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675")
  , ("auth_key", "6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494f" <> "c555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822")
  , ("randomized_password", "aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adee" <> "a73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9")
  , ("envelope", "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec" <> "1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b68" <> "0b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c")
  , ("handshake_secret", "5e723bed1e5276de2503419eba9da61ead573109c401226832398c7e08155b88" <> "5bfe7bc93451f9d887a0c1d0c19233e40a8e47b347a9ac3907f94032a4cff64f")
  , ("server_mac_key", "dad66bb9251073d17a13f8e5500f36e5998e3cde520ca0738e7085af62fd9781" <> "2eb79a745c94d0bf8a6ac17f980cf435504cf64041eeb6bb237796d2c7f81e9a")
  , ("client_mac_key", "f816fe2914f7c5b29852385615d7c7f31ac122adf202d7ccd497606d7aabd489" <> "30323d1d02b1cc9ecd456c4de6f46c7950becb18bffd921dd5876381b5486ffe")
  , ("oprf_key", "5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05")
  , ("registration_request", "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71")
  , ("registration_response", "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019" <> "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78")
  , ("registration_upload", "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675" <> "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb958" <> "64eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5" <> "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec" <> "1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b68" <> "0b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c")
  , ("KE1", "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d" <> "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc" <> "6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326")
  , ("KE2", "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471" <> "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d" <> "d6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146" <> "a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe" <> "a502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8f" <> "ed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f" <> "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1" <> "c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a" <> "292371e7809a9031743e943fb3b56f51de903552fc91fba4e7419029951c3970" <> "b2e2f0a9dea218d22e9e4e0000855bb6421aa3610d6fc0f4033a6517030d4341")
  , ("KE3", "7a026de1d6126905736c3f6d92463a08d209833eb793e46d0f7f15b3e0f62c76" <> "43763c02bbc6b8d3d15b63250cae98171e9260f1ffa789750f534ac11a0176d5")
  , ("export_key", "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62" <> "950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16")
  , ("session_key", "ae7951123ab5befc27e62e63f52cf472d6236cb386c968cc47b7e34f866aa4bc" <> "7638356a73cfce92becf39d6a7d32a1861f12130e824241fe6cab34fbd471a57")
  ]

-- | RFC 9807, appendix C.2.1: OPAQUE-3DH fake test vector 1.
fake1 :: Vector
fake1 =
  [ ("Context", "4f50415155452d504f43")
  , ("client_identity", "616c696365")
  , ("server_identity", "626f62")
  , ("oprf_seed", "743fc168d1f826ad43738933e5adb23da6fb95f95a1b069f0daa0522d0a78b61" <> "7f701fc6aa46d3e7981e70de7765dfcd6b1e13e3369a582eb8dc456b10aa53b0")
  , ("credential_identifier", "31323334")
  , ("masking_nonce", "9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6")
  , ("client_private_key", "2b98980aa95ab53a0f39f0291903d2fdf04b00c167f0814169922df873002409")
  , ("client_public_key", "84f43f9492e19c22d8bdaa4447cc3d4db1cdb5427a9f852c4707921212c36251")
  , ("server_private_key", "c788585ae8b5ba2942b693b849be0c0426384e41977c18d2e81fbe30fd7c9f06")
  , ("server_public_key", "825f832667480f08b0c9069da5083ac4d0e9ee31b49c4e0310031fea04d52966")
  , ("server_nonce", "1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12")
  , ("client_keyshare_seed", "a270dc715dc2b4612bc7864312a05c3e9788ee1bad1f276d1e15bdeb4c355e94")
  , ("server_keyshare_seed", "360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2")
  , ("masking_key", "39ebd51f0e39a07a1c2d2431995b0399bca9996c5d10014d6ebab4453dc10ce5" <> "cef38ed3df6e56bfff40c2d8dd4671c2b4cf63c3d54860f31fe40220d690bb71")
  , ("KE1", "b0a26dcaca2230b8f5e4b1bcab9c84b586140221bb8b2848486874b0be448905" <> "42d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0a" <> "b641d7f20a245a09f1d4dbb6e301661af7f352beb0791d055e48d3645232f77f")
  , ("KE2", "928f79ad8df21963e91411b9f55165ba833dea918f441db967cdc09521d22925" <> "9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6" <> "32b5ab1bff96636144faa4f9f9afaac75dd88ea99cf5175902ae3f3b2195693f" <> "165f11929ba510a5978e64dcdabecbd7ee1e4380ce270e58fea58e6462d92964" <> "a1aaef72698bca1c673baeb04cc2bf7de5f3c2f5553464552d3a0f7698a9ca7f" <> "9c5e70c6cb1f706b2f175ab9d04bbd13926e816b6811a50b4aafa9799d5ed797" <> "1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12" <> "98251c5ba55f6b0b2d58d9ff0c88fe4176484be62a96db6e2a8c4d431bd1bf27" <> "fe6c1d0537603835217d42ebf7b2581982732e74892fd28211b31ed33863f0be" <> "af75ba6f59474c0aaf9d78a60a9b2f4cd24d7ab54131b3c8efa192df6b72db4c")
  ]
