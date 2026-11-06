-- | The HKDF polyfill ("Crypto.OPAQUE.Kdf.Polyfill", used with the flag
-- @older-libsodium@) gives what libsodium's own @crypto_kdf_hkdf_sha512@
-- gives, on random inputs. This module is compiled only without the flag,
-- where "Crypto.OPAQUE.Kdf" is libsodium's; so the code behind the flag is
-- tested on every run that has libsodium 1.0.19 or later. The native build
-- turns the flag on until the toolchain builds a newer libsodium (WP5.74a2),
-- so for now no run compiles it.
module Test.KdfAgreement (spec) where

import Crypto.OPAQUE.Kdf qualified as Kdf
import Crypto.OPAQUE.Kdf.Polyfill qualified as Polyfill
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

bytes :: Int -> Gen ByteString
bytes n = BS.pack <$> vectorOf n arbitrary

someBytes :: Int -> Gen ByteString
someBytes most = chooseInt (0, most) >>= bytes

spec :: Spec
spec = describe ("the HKDF polyfill against " <> Kdf.implementation) $ do
  prop "extracts the same key" $
    forAll (someBytes 200) $ \salt -> forAll (someBytes 300) $ \ikm ->
      Polyfill.hkdfExtract salt ikm === Kdf.hkdfExtract salt ikm
  prop "expands to the same bytes" $
    forAll (bytes 64) $ \prk -> forAll (someBytes 100) $ \info -> forAll (chooseInt (1, 400)) $ \len ->
      Polyfill.hkdfExpand prk info len === Kdf.hkdfExpand prk info len
