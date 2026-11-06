-- | Known-answer tests of the key derivation constructions written in
-- "Crypto.OPAQUE.Kdf" over libsodium's hashes: @expand_message_xmd@ with
-- SHA-512 against RFC 9380's vectors (appendix K.3), and HKDF-SHA-512
-- against outputs computed independently with OpenSSL (Node 24's
-- @crypto.hkdfSync@ and @crypto.createHmac@). RFC 5869 has no vectors for
-- SHA-512; these use the inputs of its first vector.
module Test.Kdf (spec) where

import Control.Monad (forM_)
import Crypto.OPAQUE.Kdf (expandMessageXmd, hkdfExpand, hkdfExtract, i2osp)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Char (digitToInt)
import Test.Hspec

unhex :: ByteString -> ByteString
unhex h
  | BS.length h < 2 = BS.empty
  | otherwise = BS.cons (digit 0 * 16 + digit 1) (unhex (BS.drop 2 h))
  where
    digit i = fromIntegral (digitToInt (toEnum (fromIntegral (BS.index h i))))

-- | RFC 9380's vectors for @expand_message_xmd@ with SHA-512: the message,
-- the length asked for, and the output.
xmdVectors :: [(ByteString, Int, ByteString)]
xmdVectors =
  [ ("", 32, "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba")
  , ("abc", 32, "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
  , ("abcdef0123456789", 32, "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58")
  , ("q128_" <> BS.replicate 128 0x71, 32, "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3")
  , ("a512_" <> BS.replicate 512 0x61, 32, "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4")
  ,
    ( ""
    , 128
    , "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921"
        <> "b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e"
        <> "0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7e"
        <> "b00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961"
    )
  ,
    ( "abc"
    , 128
    , "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11"
        <> "bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb134"
        <> "7ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b48843"
        <> "1851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1"
    )
  ,
    ( "abcdef0123456789"
    , 128
    , "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb04"
        <> "24814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8"
        <> "f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827f"
        <> "eecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac"
    )
  ,
    ( "q128_" <> BS.replicate 128 0x71
    , 128
    , "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7"
        <> "317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78af"
        <> "df80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249c"
        <> "a7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed"
    )
  ,
    ( "a512_" <> BS.replicate 512 0x61
    , 128
    , "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2"
        <> "426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269c"
        <> "c9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c5"
        <> "2e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b"
    )
  ]

-- | RFC 5869's first vector's inputs, used with SHA-512.
ikm, salt, info :: ByteString
ikm = BS.replicate 22 0x0b
salt = BS.pack [0x00 .. 0x0c]
info = BS.pack [0xf0 .. 0xf9]

spec :: Spec
spec = do
  describe "expand_message_xmd with SHA-512 (RFC 9380, appendix K.3)" $
    forM_ xmdVectors $ \(msg, len, expected) ->
      it ("gives " <> show len <> " bytes for a message of " <> show (BS.length msg) <> " bytes") $
        expandMessageXmd msg "QUUX-V01-CS02-with-expander-SHA512-256" len `shouldBe` unhex expected

  describe "HKDF-SHA-512" $ do
    it "extracts" $
      hkdfExtract salt ikm
        `shouldBe` unhex
          ( "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
              <> "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237"
          )
    it "expands to less than one block" $
      hkdfExpand (hkdfExtract salt ikm) info 42
        `shouldBe` unhex "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
    it "expands to more than two blocks" $
      hkdfExpand (hkdfExtract salt ikm) info 150
        `shouldBe` unhex
          ( "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
              <> "cce0dff7098769cf15959867d571c1715450cb530137be3fb62f3cf32b84feba8f1eb1b563e20d9749b8"
              <> "640b8264c4b69b14ad5199115e1d609c83c6940ce5b4214a0c79946983547a35cdcc17e0daf31b647dec"
              <> "0d0e6142b1deaa036b348422068ca66631c0ca5586485a27"
          )
    it "extracts with an empty salt as with a salt of zeros, and expands an empty info" $ do
      hkdfExtract "" ikm
        `shouldBe` unhex
          ( "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b"
              <> "194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6"
          )
      hkdfExtract (BS.replicate 64 0) ikm `shouldBe` hkdfExtract "" ikm
      hkdfExpand (hkdfExtract "" ikm) "" 42
        `shouldBe` unhex "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac"

  describe "I2OSP" $
    it "writes big-endian bytes" $ do
      i2osp 2 0x1234 `shouldBe` BS.pack [0x12, 0x34]
      i2osp 1 255 `shouldBe` BS.pack [255]
      i2osp 2 65535 `shouldBe` BS.pack [255, 255]
