-- | The opaque package's tests: the RFCs' test vectors, known-answer tests
-- of the key derivations, round trips with real random values, the cases
-- other implementations test beyond the vectors, QuickCheck properties, and
-- the memory secrets are kept in.
-- They run natively and, under Node, as wasm.
module Main (main) where

import Test.Hardening qualified
import Test.Hspec
import Test.Kdf qualified
import Test.KdfAgreement qualified
import Test.Memory qualified
import Test.Properties qualified
import Test.RoundTrip qualified
import Test.Vectors qualified

main :: IO ()
main = hspec $ do
  describe "Test.Vectors" Test.Vectors.spec
  describe "Test.Kdf" Test.Kdf.spec
  describe "Test.KdfAgreement" Test.KdfAgreement.spec
  describe "Test.RoundTrip" Test.RoundTrip.spec
  describe "Test.Hardening" Test.Hardening.spec
  describe "Test.Properties" Test.Properties.spec
  describe "Test.Memory" Test.Memory.spec
