{-# LANGUAGE CPP #-}

-- | The key derivation constructions OPAQUE is specified with: HKDF-SHA-512
-- (RFC 5869) and @expand_message_xmd@ with SHA-512 (RFC 9380, section
-- 5.3.1).
--
-- HKDF is libsodium's @crypto_kdf_hkdf_sha512_*@, which came in 1.0.19.
-- With the package's flag @older-libsodium@ it is the Haskell polyfill in
-- "Crypto.OPAQUE.Kdf.Polyfill" instead, over libsodium's HMAC-SHA-512, so
-- that the package builds against 1.0.18 (Debian 12 and Ubuntu 24.04). This
-- module is the one place that chooses.
--
-- @expand_message_xmd@ is written here over libsodium's SHA-512 in every
-- build: libsodium has no hash-to-group for ristretto255 that takes a
-- domain separation tag (1.0.22 has @crypto_core_ristretto255_from_hash@
-- only, and @from_string@ for edwards25519, not ristretto255), so
-- @hash_to_ristretto255@ is @expand_message_xmd@ followed by
-- @from_hash@, as RFC 9380 defines it. The tests check it against RFC
-- 9380's vectors (appendix K.3).
--
-- The functions whose names end in @Into@ write into memory the caller
-- gives and zero their own temporaries; the others, over 'ByteString's, are
-- for public values and the tests.
module Crypto.OPAQUE.Kdf
  ( hkdfExtractInto
  , hkdfExpandInto
  , expandMessageXmdInto
  , i2osp
  , implementation
  , hkdfExtract
  , hkdfExpand
  , expandMessageXmd
  )
where

import Control.Monad (forM_, when)
import Crypto.OPAQUE.Secret (withScrubbed)
import Crypto.OPAQUE.Sodium (Part (..), hashBytes, publicBytes, sha512Into, withPart)
import Data.Bits (shiftR, xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafeDupablePerformIO)
#if defined(OLDER_LIBSODIUM)
import Crypto.OPAQUE.Kdf.Polyfill (hkdfExpandInto, hkdfExtractInto)
#else
import Control.Monad (void)
import Crypto.OPAQUE.Sodium (partLength)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Foreign.C.Types (CChar, CInt (..), CSize (..), CUChar)

foreign import ccall unsafe "crypto_kdf_hkdf_sha512_extract"
  c_hkdf_extract :: Ptr CUChar -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall unsafe "crypto_kdf_hkdf_sha512_expand"
  c_hkdf_expand :: Ptr CUChar -> CSize -> Ptr CChar -> CSize -> Ptr CUChar -> IO CInt

-- | 'hkdfExtractInto' is HKDF-Extract with SHA-512: the pseudorandom key,
-- 64 bytes at @out@, from a salt and the @n@ bytes of input keying material
-- at @ikm@.
hkdfExtractInto :: Ptr Word8 -> ByteString -> Ptr Word8 -> Int -> IO ()
hkdfExtractInto out salt ikm n =
  unsafeUseAsCStringLen salt $ \(s, sn) ->
    void (c_hkdf_extract (castPtr out) (castPtr s) (fromIntegral sn) (castPtr ikm) (fromIntegral n))

-- | 'hkdfExpandInto' is HKDF-Expand with SHA-512: @len@ bytes at @out@ from
-- a pseudorandom key of 64 bytes and an info string. More than 255 blocks
-- is an error; OPAQUE never asks for more than three.
hkdfExpandInto :: Ptr Word8 -> Int -> Part -> ByteString -> IO ()
hkdfExpandInto out len prk info
  | partLength prk /= hashBytes = ioError (userError "opaque: hkdfExpand takes a key of 64 bytes")
  | otherwise =
      withPart prk $ \k _ ->
        unsafeUseAsCStringLen info $ \(i, n) -> do
          r <- c_hkdf_expand (castPtr out) (fromIntegral len) i (fromIntegral n) k
          when (r /= 0) (ioError (userError "opaque: hkdfExpand refused its arguments"))
#endif

-- | 'implementation' names the HKDF this build uses, for the tests' output.
implementation :: String
#if defined(OLDER_LIBSODIUM)
implementation = "the Haskell polyfill (older-libsodium)"
#else
implementation = "libsodium's crypto_kdf_hkdf_sha512"
#endif

-- | 'i2osp' writes a non-negative integer as @n@ big-endian bytes: the
-- RFCs' I2OSP. It is used only for lengths and counters. It keeps the low
-- @n@ bytes of a larger integer, so every caller refuses inputs whose length
-- does not fit before it gets here.
i2osp :: Int -> Int -> ByteString
i2osp n x = BS.pack [fromIntegral (x `shiftR` (8 * i)) | i <- [n - 1, n - 2 .. 0]]

-- | 'expandMessageXmdInto' is @expand_message_xmd@ with SHA-512: @len@
-- uniform bytes at @out@ from a message (the concatenation of the parts) and
-- a domain separation tag. The blocks b_0, b_i and their XOR are written in
-- a buffer that is zeroed before it returns. Arguments out of the RFC's
-- range are an error; this package never gives such.
expandMessageXmdInto :: Ptr Word8 -> Int -> [Part] -> ByteString -> IO ()
expandMessageXmdInto out len msg dst
  | ell > 255 || len > 65535 || BS.length dst > 255 =
      ioError (userError "opaque: expandMessageXmd arguments out of range")
  | otherwise =
      withScrubbed (3 * hashBytes) $ \buf -> do
        let b0 = buf
            bi = buf `plusPtr` hashBytes
            mixed = buf `plusPtr` (2 * hashBytes)
        sha512Into b0 ([Pub zPad] <> msg <> [Pub (i2osp 2 len <> i2osp 1 0), Pub dstPrime])
        sha512Into bi [Mem b0 hashBytes, Pub (i2osp 1 1), Pub dstPrime]
        forM_ [1 .. ell] $ \i -> do
          when (i > 1) $ do
            forM_ [0 .. hashBytes - 1] $ \j -> do
              x <- peekByteOff b0 j :: IO Word8
              y <- peekByteOff bi j :: IO Word8
              pokeByteOff mixed j (x `xor` y)
            sha512Into bi [Mem mixed hashBytes, Pub (i2osp 1 i), Pub dstPrime]
          let offset = (i - 1) * hashBytes
          copyBytes (out `plusPtr` offset) bi (min hashBytes (len - offset))
  where
    ell = (len + hashBytes - 1) `div` hashBytes
    dstPrime = dst <> i2osp 1 (BS.length dst)
    zPad = BS.replicate 128 0

-- | 'hkdfExtract' is 'hkdfExtractInto' over bytes.
hkdfExtract :: ByteString -> ByteString -> ByteString
hkdfExtract salt ikm =
  unsafeDupablePerformIO . publicBytes hashBytes $ \o ->
    withPart (Pub ikm) (\p n -> hkdfExtractInto o salt (castPtr p) n)

-- | 'hkdfExpand' is 'hkdfExpandInto' over bytes.
hkdfExpand :: ByteString -> ByteString -> Int -> ByteString
hkdfExpand prk info len = unsafeDupablePerformIO (publicBytes len (\o -> hkdfExpandInto o len (Pub prk) info))

-- | 'expandMessageXmd' is 'expandMessageXmdInto' over bytes.
expandMessageXmd :: ByteString -> ByteString -> Int -> ByteString
expandMessageXmd msg dst len = unsafeDupablePerformIO (publicBytes len (\o -> expandMessageXmdInto o len [Pub msg] dst))
