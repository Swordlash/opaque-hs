-- | The package's memory for secrets ("Crypto.OPAQUE.Secret"): a scratch
-- buffer is zero after its operation, whether the operation succeeded,
-- failed or threw; a secret prints as @<secret>@, compares by content, and
-- is zero once scrubbed; and values derived inside a scratch buffer are
-- still right after garbage collections, which would show a result that
-- reads the buffer after it was zeroed or freed.
module Test.Memory (spec) where

import Control.Exception (ErrorCall (..), IOException, evaluate, throwIO, try)
import Crypto.OPAQUE.Internal
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Secret
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.Char (digitToInt)
import Data.Word (Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr)
import System.Mem (performMajorGC)
import Test.Hspec

unhex :: ByteString -> ByteString
unhex h
  | BS.length h < 2 = BS.empty
  | otherwise = BS.cons (digit 0 * 16 + digit 1) (unhex (BS.drop 2 h))
  where
    digit i = fromIntegral (digitToInt (toEnum (fromIntegral (BS.index h i))))

-- | The bytes of memory, copied.
bytesAt :: Ptr Word8 -> Int -> IO ByteString
bytesAt p n = BSI.create n (\q -> copyBytes q p n)

-- | Run an operation in a scratch buffer the test owns (so that reading it
-- afterwards reads live memory), writing secrets into every piece it takes,
-- and give back the buffer as it is after the operation.
afterScratch :: (Scratch -> IO a) -> IO (Either ErrorCall a, ByteString)
afterScratch op =
  allocaBytes 256 $ \p -> do
    fillBytes p 0xa5 256
    r <- try (withScratchIn p 256 op)
    (,) r <$> bytesAt p 256

spec :: Spec
spec = do
  describe "a scratch buffer" $ do
    let writing s = do
          a <- scratch s 64
          fillBytes a 0x5a 64
          b <- scratch s 32
          fillBytes b 0x3c 32
    it "is zero after its operation succeeded" $ do
      (r, left) <- afterScratch (\s -> writing s >> pure (Right ()))
      r `shouldBe` Right (Right () :: Either Error ())
      left `shouldBe` BS.replicate 256 0
    it "is zero after its operation failed with an error" $ do
      (r, left) <- afterScratch (\s -> writing s >> pure (Left EnvelopeRecoveryError))
      r `shouldBe` Right (Left EnvelopeRecoveryError :: Either Error ())
      left `shouldBe` BS.replicate 256 0
    it "is zero after its operation threw" $ do
      (r, left) <- afterScratch (\s -> writing s >> throwIO (ErrorCall "in the middle") :: IO ())
      r `shouldBe` Left (ErrorCall "in the middle")
      left `shouldBe` BS.replicate 256 0
    it "refuses to hand out more than it has, and is zero afterwards" $ do
      (r, left) <- afterScratch $ \s -> do
        writing s
        tooMuch <- try (scratch s 200)
        pure (either (\(_ :: IOException) -> True) (const False) tooMuch)
      r `shouldBe` Right True
      left `shouldBe` BS.replicate 256 0

  describe "a secret" $ do
    it "prints as <secret> and compares by content" $ do
      a <- secretFromBytes "the same bytes"
      b <- secretFromBytes "the same bytes"
      c <- secretFromBytes "other bytes!!!"
      show a `shouldBe` "<secret>"
      (a == b, a == c) `shouldBe` (True, False)
    it "is zero once scrubbed, and its copy is the bytes it was made of" $ do
      a <- secretFromBytes "some secret bytes"
      copySecret a `shouldReturn` "some secret bytes"
      scrubSecret a
      copySecret a `shouldReturn` BS.replicate 17 0
    it "made by a step is still its value after garbage collections" $ do
      -- RFC 9497's first vector: Evaluate goes through two scratch buffers.
      let k = unhex "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
      output <- evaluate (OPRF.evaluate k (BS.singleton 0))
      _ <- evaluate (maybe 0 BS.length output)
      setup <- either (error . show) pure =<< generateServerSetup
      (rst, request) <- either (error . show) pure =<< registrationRequest "pw"
      response <- either (error . show) pure (registrationResponse setup (CredentialId "u") request)
      (record, ExportKey exported) <- either (error . show) pure =<< finalizeRegistration config rst response defaultIdentities
      made <- copySecret exported
      let churn = do
            performMajorGC
            -- Other steps take and zero scratch buffers meanwhile.
            mapM_ (\i -> OPRF.evaluate k (BS.singleton i) `seq` pure ()) [1 .. 50]
            performMajorGC
      churn
      churn
      output `shouldBe` Just (unhex "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
      copySecret exported `shouldReturn` made
      (cst, ke1) <- either (error . show) pure =<< clientStart "pw"
      (_, ke2) <- either (error . show) pure =<< serverRespond config setup (Just record) (CredentialId "u") ke1 defaultIdentities
      churn
      case clientFinish config cst ke2 defaultIdentities of
        Left e -> expectationFailure (show e)
        Right (_, _, ExportKey again) -> do
          churn
          copySecret again `shouldReturn` made
  where
    config = Config {context = "memory", ksf = Identity}
