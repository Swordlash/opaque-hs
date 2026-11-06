-- | Built with the flag @older-libsodium@, the package has no libsodium HKDF
-- to compare the polyfill with: "Crypto.OPAQUE.Kdf" is the polyfill itself.
-- The comparison runs in the builds without the flag (test-libsodium/).
module Test.KdfAgreement (spec) where

import Crypto.OPAQUE.Kdf qualified as Kdf
import Test.Hspec

spec :: Spec
spec =
  describe ("the HKDF polyfill against libsodium's (this build uses " <> Kdf.implementation <> ")")
    $ it "is compared only in builds without older-libsodium"
    $ pendingWith "built with older-libsodium: libsodium's HKDF is not linked"
