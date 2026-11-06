-- | The opaque package's tests: the RFCs' test vectors, and round trips
-- with real random values. They run natively and, under Node, as wasm.
module Main (main) where

import Test.Hspec
import Test.RoundTrip qualified
import Test.Vectors qualified

main :: IO ()
main = hspec $ do
  describe "Test.Vectors" Test.Vectors.spec
  describe "Test.RoundTrip" Test.RoundTrip.spec
