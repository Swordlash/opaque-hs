-- | The opaque package's tests: the RFCs' test vectors, known-answer tests
-- of the key derivations, round trips with real random values, the cases
-- other implementations test beyond the vectors, and QuickCheck properties.
-- They run natively and, under Node, as wasm.
module Main (main) where

import Test.Hardening qualified
import Test.Hspec
import Test.Kdf qualified
import Test.Properties qualified
import Test.RoundTrip qualified
import Test.Vectors qualified

main :: IO ()
main = hspec $ do
  describe "Test.Vectors" Test.Vectors.spec
  describe "Test.Kdf" Test.Kdf.spec
  describe "Test.RoundTrip" Test.RoundTrip.spec
  describe "Test.Hardening" Test.Hardening.spec
  describe "Test.Properties" Test.Properties.spec
