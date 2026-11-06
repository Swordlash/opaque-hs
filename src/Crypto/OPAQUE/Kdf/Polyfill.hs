-- | HKDF-SHA-512 (RFC 5869) written over libsodium's HMAC-SHA-512, for a
-- libsodium older than 1.0.19, which has no @crypto_kdf_hkdf_sha512_*@
-- (Debian 12 and Ubuntu 24.04 ship 1.0.18). "Crypto.OPAQUE.Kdf" uses it
-- when the package is built with the flag @older-libsodium@, and libsodium's
-- own HKDF otherwise. It is compiled either way, and the tests compare it
-- with libsodium's whenever libsodium's is there.
--
-- HKDF is not a primitive: Extract is one HMAC, Expand a chain of them.
-- Expand's blocks are written in a buffer that is zeroed before it returns.
module Crypto.OPAQUE.Kdf.Polyfill
  ( hkdfExtractInto
  , hkdfExpandInto
  , hkdfExtract
  , hkdfExpand
  )
where

import Control.Monad (forM_)
import Crypto.OPAQUE.Secret (withScrubbed)
import Crypto.OPAQUE.Sodium (Part (..), hashBytes, hmacSha512Into, partLength, publicBytes)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | 'hkdfExtractInto' is HKDF-Extract with SHA-512: HMAC keyed by the salt
-- over the input keying material, @n@ bytes at @ikm@, written as 64 bytes
-- at @out@. An empty salt is HMAC's key of zeros, as RFC 5869 says.
hkdfExtractInto :: Ptr Word8 -> ByteString -> Ptr Word8 -> Int -> IO ()
hkdfExtractInto out salt ikm n = hmacSha512Into out (Pub salt) [Mem ikm n]

-- | 'hkdfExpandInto' is HKDF-Expand with SHA-512: @len@ bytes at @out@ from
-- a pseudorandom key and an info string. More than 255 blocks is an
-- error, as RFC 5869 says; OPAQUE never asks for more than three. The key
-- must be 64 bytes, as libsodium's @crypto_kdf_hkdf_sha512_expand@ requires,
-- so that the two implementations take the same arguments.
hkdfExpandInto :: Ptr Word8 -> Int -> Part -> ByteString -> IO ()
hkdfExpandInto out len prk info
  | len > 255 * hashBytes = ioError (userError "opaque: hkdfExpand asked for too many bytes")
  | partLength prk /= hashBytes = ioError (userError "opaque: hkdfExpand takes a key of 64 bytes")
  | otherwise =
      withScrubbed hashBytes $ \t ->
        forM_ [1 .. blocks] $ \i -> do
          let previous = [Mem t hashBytes | i > 1]
          hmacSha512Into t prk (previous <> [Pub info, Pub (BS.singleton (fromIntegral i))])
          let offset = (i - 1) * hashBytes
          copyBytes (out `plusPtr` offset) t (min hashBytes (len - offset))
  where
    blocks = (len + hashBytes - 1) `div` hashBytes

-- | 'hkdfExtract' is 'hkdfExtractInto' over bytes, for the tests.
hkdfExtract :: ByteString -> ByteString -> ByteString
hkdfExtract salt ikm =
  unsafeDupablePerformIO . publicBytes hashBytes $ \o ->
    hmacSha512Into o (Pub salt) [Pub ikm]

-- | 'hkdfExpand' is 'hkdfExpandInto' over bytes, for the tests.
hkdfExpand :: ByteString -> ByteString -> Int -> ByteString
hkdfExpand prk info len = unsafeDupablePerformIO (publicBytes len (\o -> hkdfExpandInto o len (Pub prk) info))
