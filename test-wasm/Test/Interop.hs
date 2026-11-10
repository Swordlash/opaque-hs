-- | The tests against @serenity-kit/opaque@ on wasm32-wasi, where there
-- are none: they drive a Node process (@test-native\/Test\/Interop.hs@),
-- and a WASI program starts no process. One pending example says so, so
-- that a run's count shows what it left out.
module Test.Interop (spec) where

import Test.Hspec

spec :: Spec
spec =
  it "runs against @serenity-kit/opaque under Node" $
    pendingWith "skipped on wasm32-wasi: a WASI program starts no process; the native test suite runs these"
