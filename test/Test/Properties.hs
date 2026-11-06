-- | Properties of the opaque package checked on random inputs with
-- QuickCheck: every message and state survives an encoding and a decoding
-- at its exact length, decoding arbitrary bytes never throws, the OPRF's
-- blinded protocol gives the same output as evaluating it directly, and the
-- group's key pairs and Diffie-Hellman agree.
module Test.Properties (spec) where

import Control.Exception (evaluate)
import Crypto.OPAQUE.Internal
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Sodium (scalarMult, scalarMultBase, scalarReduce)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

-- | 'bytes' is a generator of @n@ arbitrary bytes.
bytes :: Int -> Gen ByteString
bytes n = BS.pack <$> vectorOf n arbitrary

-- | 'someBytes' is a generator of arbitrary bytes of any length up to 400,
-- longer than every encoding in the package.
someBytes :: Gen ByteString
someBytes = sized $ \_ -> chooseInt (0, 400) >>= bytes

-- | 'scalar' is a generator of scalars: 64 random bytes reduced modulo the
-- group's order, as libsodium's own random scalars are made. A zero is
-- possible only with negligible probability.
scalar :: Gen ByteString
scalar = scalarReduce <$> bytes 64

-- | 'password' is a generator of short passwords, the empty one included.
password :: Gen ByteString
password = chooseInt (0, 40) >>= bytes

-- | 'Transcript' is every message and state of one registration and one
-- login, made from random inputs with no stretching (the properties are
-- about the encodings, not the KSF).
data Transcript = Transcript
  { request :: RegistrationRequest
  , response :: RegistrationResponse
  , record :: RegistrationRecord
  , regState :: ClientRegState
  , ke1 :: KE1
  , ke2 :: KE2
  , ke3 :: KE3
  , clientState :: ClientLoginState
  , serverState :: ServerLoginState
  , setup :: ServerSetup
  }

transcript :: Gen Transcript
transcript = do
  fakeKey <- scalar
  fakeMask <- bytes 64
  seed <- bytes 64
  keySeed <- bytes 32
  r1 <- scalar
  r2 <- scalar
  envelopeNonce <- bytes 32
  clientNonce <- bytes 32
  clientSeed <- bytes 32
  random <- ServerRandom <$> bytes 32 <*> bytes 32 <*> bytes 32
  pw <- password
  let config = Config {context = "opaque-properties", ksf = Identity}
      cid = CredentialId "someone"
      made = do
        fake <- maybe (Left DeriveKeyPairError) Right (fakeRecordWith fakeKey fakeMask)
        s <- serverSetupWith seed keySeed fake
        (regSt, req) <- registrationRequestWith r1 pw
        resp <- registrationResponse s cid req
        (rec, _) <- finalizeRegistrationWith config envelopeNonce regSt resp defaultIdentities
        (cst, k1) <- clientStartWith r2 clientNonce clientSeed pw
        (sst, k2) <- serverRespondWith config s rec cid random k1 defaultIdentities
        (k3, _, _) <- clientFinish config cst k2 defaultIdentities
        pure (Transcript req resp rec regSt k1 k2 k3 cst sst s)
  either (const discard) pure made

-- | 'roundTrips' says that a value's encoding has the expected length and
-- decodes to the value.
roundTrips :: (Encoding a, Eq a, Show a) => Int -> a -> Property
roundTrips n x =
  counterexample (show x) $
    BS.length (encode x) === n .&&. decode (encode x) === Right x

-- | 'neverThrows' says that decoding the bytes gives an answer, an error or a
-- value whose encoding is those same bytes, and never throws.
neverThrows :: forall a. (Encoding a) => (ByteString -> Either Error a) -> ByteString -> Property
neverThrows dec bs = ioProperty $ do
  answer <- evaluate (either (const True) (\x -> encode x == bs) (dec bs))
  pure (counterexample (show (BS.unpack bs)) answer)

spec :: Spec
spec = do
  describe "encodings" $ do
    prop "round trip at their exact lengths" $
      forAllBlind transcript $ \t ->
        conjoin
          [ roundTrips 32 t.request
          , roundTrips 64 t.response
          , roundTrips 192 t.record
          , roundTrips 96 t.ke1
          , roundTrips 320 t.ke2
          , roundTrips 64 t.ke3
          ]
    prop "of states round trip too" $
      forAllBlind transcript $ \t ->
        let reencodes :: forall a. (Encoding a) => (ByteString -> Either Error a) -> a -> Property
            reencodes dec x = fmap encode (dec (encode x)) === Right (encode x)
         in conjoin [reencodes (decode @ClientRegState) t.regState, reencodes decode t.clientState, reencodes decode t.serverState, reencodes decode t.setup]
    prop "decoding arbitrary bytes never throws" $
      forAll someBytes $ \bs ->
        conjoin
          [ neverThrows (decode @RegistrationRequest) bs
          , neverThrows (decode @RegistrationResponse) bs
          , neverThrows (decode @RegistrationRecord) bs
          , neverThrows (decode @KE1) bs
          , neverThrows (decode @KE2) bs
          , neverThrows (decode @KE3) bs
          , neverThrows (decode @ClientRegState) bs
          , neverThrows (decode @ClientLoginState) bs
          , neverThrows (decode @ServerLoginState) bs
          , neverThrows (decode @ServerSetup) bs
          ]
    prop "decoding arbitrary bytes of an encoding's exact length never throws" $
      forAll (bytes 32) $ \b32 -> forAll (bytes 96) $ \b96 -> forAll (bytes 192) $ \b192 -> forAll (bytes 320) $ \b320 ->
        conjoin
          [ neverThrows (decode @RegistrationRequest) b32
          , neverThrows (decode @KE1) b96
          , neverThrows (decode @RegistrationRecord) b192
          , neverThrows (decode @KE2) b320
          ]

  describe "the OPRF" $
    prop "gives through Blind, BlindEvaluate and Finalize what Evaluate gives" $
      forAll scalar $ \k -> forAll scalar $ \r -> forAll password $ \input ->
        let viaProtocol = do
              (_, blinded) <- OPRF.blindWith r input
              evaluated <- OPRF.blindEvaluate k blinded
              OPRF.finalize input r evaluated
         in viaProtocol === OPRF.evaluate k input .&&. viaProtocol =/= Nothing

  describe "key pairs" $ do
    prop "derived from a seed have the public key of the private key" $
      forAll (bytes 32) $ \seed ->
        case deriveDiffieHellmanKeyPair seed of
          Left e -> counterexample (show e) False
          Right (sk, pk) -> scalarMultBase sk === Just pk
    prop "agree on Diffie-Hellman: a times bG is b times aG" $
      forAll scalar $ \a -> forAll scalar $ \b ->
        let shared x y = scalarMult x =<< scalarMultBase y
         in shared a b === shared b a .&&. shared a b =/= Nothing
