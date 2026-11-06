-- | The key derivation constructions OPAQUE is specified with, built from
-- libsodium's HMAC-SHA-512 and SHA-512.
--
-- HKDF (RFC 5869) and @expand_message_xmd@ (RFC 9380, section 5.3.1) are
-- not primitives: each is a few lines of concatenation and calls to a hash
-- or a MAC. They are written here, over 'hmacSha512' and 'sha512', because
-- libsodium 1.0.18, the oldest this package supports (the one the build
-- machines' distribution packages), has neither: @crypto_kdf_hkdf_sha512_*@
-- came in 1.0.19, and libsodium has no @expand_message_xmd@ with SHA-512.
-- The tests check both against published known-answer vectors: RFC 9380's
-- appendix K.3 for @expand_message_xmd@, and HKDF-SHA-512 outputs computed
-- independently with OpenSSL (through Node's @crypto.hkdfSync@).
module Crypto.OPAQUE.Kdf
  ( hkdfExtract
  , hkdfExpand
  , expandMessageXmd
  , i2osp
  )
where

import Crypto.OPAQUE.Sodium (hashBytes, hmacSha512, sha512)
import Data.Bits (shiftR, xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS

-- | 'i2osp' writes a non-negative integer as @n@ big-endian bytes: the
-- RFCs' I2OSP. It is used only for lengths and counters. It keeps the low
-- @n@ bytes of a larger integer, so every caller refuses inputs whose length
-- does not fit before it gets here.
i2osp :: Int -> Int -> ByteString
i2osp n x = BS.pack [fromIntegral (x `shiftR` (8 * i)) | i <- [n - 1, n - 2 .. 0]]

-- | 'hkdfExtract' is HKDF-Extract with SHA-512: HMAC keyed by the salt over
-- the input keying material. An empty salt is HMAC's key of zeros, as RFC
-- 5869 says.
hkdfExtract :: ByteString -> ByteString -> ByteString
hkdfExtract salt ikm = hmacSha512 salt [ikm]

-- | 'hkdfExpand' is HKDF-Expand with SHA-512: @len@ bytes of output keying
-- material from a pseudorandom key and an info string. OPAQUE never asks
-- for more than 255 blocks, which RFC 5869 forbids.
hkdfExpand :: ByteString -> ByteString -> Int -> ByteString
hkdfExpand prk info len
  | len > 255 * hashBytes = error "opaque: hkdfExpand asked for too many bytes"
  | otherwise = BS.take len (BS.concat (go 1 BS.empty))
  where
    blocks = (len + hashBytes - 1) `div` hashBytes
    go i previous
      | i > blocks = []
      | otherwise =
          let t = hmacSha512 prk [previous, info, BS.singleton (fromIntegral i)]
           in t : go (i + 1) t

-- | 'expandMessageXmd' is @expand_message_xmd@ of RFC 9380 with SHA-512:
-- @len@ uniformly random bytes from a message and a domain separation tag.
-- RFC 9497 uses it with @len@ 64 to hash to the group and to scalars.
-- SHA-512's block is 128 bytes, the length of the zero padding in front.
expandMessageXmd :: ByteString -> ByteString -> Int -> ByteString
expandMessageXmd msg dst len
  | ell > 255 || len > 65535 || BS.length dst > 255 =
      error "opaque: expandMessageXmd arguments out of range"
  | otherwise = BS.take len (BS.concat (b1 : go 2 b1))
  where
    ell = (len + hashBytes - 1) `div` hashBytes
    dstPrime = dst <> i2osp 1 (BS.length dst)
    zPad = BS.replicate 128 0
    b0 = sha512 [zPad, msg, i2osp 2 len, i2osp 1 0, dstPrime]
    b1 = sha512 [b0, i2osp 1 1, dstPrime]
    go i previous
      | i > ell = []
      | otherwise =
          let b = sha512 [BS.pack (BS.zipWith xor b0 previous), i2osp 1 i, dstPrime]
           in b : go (i + 1) b
