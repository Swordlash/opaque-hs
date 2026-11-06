-- | The libsodium functions the protocol is built from, and nothing else.
--
-- Every cryptographic primitive OPAQUE needs comes from libsodium: the
-- ristretto255 group (hash-to-group, scalars, scalar multiplication),
-- SHA-512, HMAC-SHA-512, Argon2id and the system's random numbers. This
-- module binds the dozen C functions with @ccall@ imports and wraps each one
-- in a function over 'ByteString's. Nothing here implements a primitive.
--
-- The deterministic functions are pure: they read their inputs, write a
-- fresh buffer and touch no other state. libsodium is initialised once,
-- before the first call, by 'sodiumReady'.
module Crypto.OPAQUE.Sodium
  ( -- * Sizes
    elementBytes
  , scalarBytes
  , hashBytes

    -- * SHA-512 and HMAC-SHA-512
  , sha512
  , hmacSha512

    -- * ristretto255
  , fromHash
  , isValidElement
  , scalarReduce
  , scalarInvert
  , scalarMult
  , scalarMultBase
  , randomScalar

    -- * Argon2id
  , argon2id

    -- * Randomness and comparison
  , randomBytes
  , constantTimeEqual
  )
where

import Control.Exception (evaluate)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word64)
import Foreign.C.Types (CInt (..), CSize (..), CUChar, CULLong (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)

foreign import ccall unsafe "sodium_init" c_sodium_init :: IO CInt

foreign import ccall unsafe "crypto_hash_sha512"
  c_hash_sha512 :: Ptr CUChar -> Ptr CUChar -> CULLong -> IO CInt

foreign import ccall unsafe "crypto_auth_hmacsha512_statebytes"
  c_hmacsha512_statebytes :: IO CSize

foreign import ccall unsafe "crypto_auth_hmacsha512_init"
  c_hmacsha512_init :: Ptr () -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall unsafe "crypto_auth_hmacsha512_update"
  c_hmacsha512_update :: Ptr () -> Ptr CUChar -> CULLong -> IO CInt

foreign import ccall unsafe "crypto_auth_hmacsha512_final"
  c_hmacsha512_final :: Ptr () -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_core_ristretto255_from_hash"
  c_from_hash :: Ptr CUChar -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_core_ristretto255_is_valid_point"
  c_is_valid_point :: Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_core_ristretto255_scalar_reduce"
  c_scalar_reduce :: Ptr CUChar -> Ptr CUChar -> IO ()

foreign import ccall unsafe "crypto_core_ristretto255_scalar_invert"
  c_scalar_invert :: Ptr CUChar -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_core_ristretto255_scalar_random"
  c_scalar_random :: Ptr CUChar -> IO ()

foreign import ccall unsafe "crypto_scalarmult_ristretto255"
  c_scalarmult :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_scalarmult_ristretto255_base"
  c_scalarmult_base :: Ptr CUChar -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "crypto_pwhash_alg_argon2id13"
  c_pwhash_alg_argon2id13 :: IO CInt

-- Argon2id runs for a second or so: a safe call lets the rest of the
-- program's threads go on meanwhile.
foreign import ccall safe "crypto_pwhash"
  c_pwhash
    :: Ptr CUChar
    -> CULLong
    -> Ptr CUChar
    -> CULLong
    -> Ptr CUChar
    -> CULLong
    -> CSize
    -> CInt
    -> IO CInt

foreign import ccall unsafe "randombytes_buf"
  c_randombytes_buf :: Ptr () -> CSize -> IO ()

foreign import ccall unsafe "sodium_memcmp"
  c_memcmp :: Ptr () -> Ptr () -> CSize -> IO CInt

foreign import ccall unsafe "sodium_memzero"
  c_memzero :: Ptr () -> CSize -> IO ()

-- | The size of an encoded ristretto255 element, 32 bytes (the RFCs' Noe and
-- Npk).
elementBytes :: Int
elementBytes = 32

-- | The size of an encoded ristretto255 scalar, 32 bytes (Nok and Nsk).
scalarBytes :: Int
scalarBytes = 32

-- | The size of a SHA-512 digest and of an HMAC-SHA-512 tag, 64 bytes (Nh,
-- Nm and Nx).
hashBytes :: Int
hashBytes = 64

-- | 'sodiumReady' is libsodium's initialisation, run once. @sodium_init@
-- picks the fastest implementation of each primitive for the processor and
-- opens the source of random numbers. It may be called any number of times
-- and from any thread; this keeps it to one call per program.
sodiumReady :: ()
sodiumReady = unsafePerformIO $ do
  r <- c_sodium_init
  if r < 0 then ioError (userError "opaque: sodium_init failed") else pure ()
{-# NOINLINE sodiumReady #-}

-- | Run a libsodium call after the library is initialised.
sodium :: IO a -> IO a
sodium act = evaluate sodiumReady >> act

-- | Read a ByteString as a pointer to unsigned bytes with its length.
withBytes :: ByteString -> (Ptr CUChar -> Int -> IO a) -> IO a
withBytes bs f = unsafeUseAsCStringLen bs (\(p, n) -> f (castPtr p) n)

-- | Make a buffer of @n@ bytes filled by a call that cannot fail.
fresh :: Int -> (Ptr CUChar -> IO ()) -> IO ByteString
fresh n f = BSI.create n (f . castPtr)

-- | Make a buffer of @n@ bytes filled by a call that reports failure with a
-- negative result; the buffer is wiped and dropped on failure.
freshOr :: Int -> (Ptr CUChar -> IO CInt) -> IO (Maybe ByteString)
freshOr n f = do
  (bs, ok) <- BSI.createUptoN' n $ \p -> do
    r <- f (castPtr p)
    if r == 0
      then pure (n, True)
      else c_memzero (castPtr p) (fromIntegral n) >> pure (0, False)
  pure (if ok then Just bs else Nothing)

-- | 'sha512' is SHA-512 over the concatenation of the parts.
sha512 :: [ByteString] -> ByteString
sha512 parts = unsafeDupablePerformIO . sodium $
  withBytes input $ \i n ->
    fresh hashBytes $ \o -> () <$ c_hash_sha512 o i (fromIntegral n)
  where
    input = BS.concat parts

-- | The size of libsodium's HMAC-SHA-512 state, asked of the library once.
hmacStateBytes :: Int
hmacStateBytes = fromIntegral (unsafePerformIO c_hmacsha512_statebytes)
{-# NOINLINE hmacStateBytes #-}

-- | 'hmacSha512' is HMAC-SHA-512 with a key of any length, over the
-- concatenation of the parts. It goes through the streaming interface
-- because libsodium's one-shot @crypto_auth_hmacsha512@ takes a key of
-- exactly 32 bytes, and OPAQUE's keys are 64. The state is wiped after use.
hmacSha512 :: ByteString -> [ByteString] -> ByteString
hmacSha512 key parts = unsafeDupablePerformIO . sodium $
  allocaBytes hmacStateBytes $ \st ->
    withBytes key $ \k kn -> do
      _ <- c_hmacsha512_init st k (fromIntegral kn)
      mapM_ (\part -> withBytes part (\p n -> c_hmacsha512_update st p (fromIntegral n))) parts
      out <- fresh hashBytes (\o -> () <$ c_hmacsha512_final st o)
      c_memzero st (fromIntegral hmacStateBytes)
      pure out

-- | 'fromHash' maps 64 uniformly random bytes to a ristretto255 element: the
-- one-way map of RFC 9496, which @hash_to_ristretto255@ of RFC 9380 applies
-- to the output of @expand_message_xmd@.
fromHash :: ByteString -> ByteString
fromHash h
  | BS.length h /= hashBytes = error "opaque: fromHash takes 64 bytes"
  | otherwise =
      unsafeDupablePerformIO . sodium $
        withBytes h $
          \i _ -> fresh elementBytes (\o -> () <$ c_from_hash o i)

-- | 'isValidElement' says whether the bytes are the canonical encoding of a
-- ristretto255 element other than the identity. libsodium's check accepts
-- the identity (32 zero bytes), which RFC 9497's DeserializeElement must
-- refuse, so the identity is refused here as well.
isValidElement :: ByteString -> Bool
isValidElement e =
  BS.length e == elementBytes
    && BS.any (/= 0) e
    && unsafeDupablePerformIO (sodium (withBytes e (\p _ -> (== 1) <$> c_is_valid_point p)))

-- | 'scalarReduce' reads 64 bytes as a little-endian integer and reduces it
-- modulo the group's order: HashToScalar's last step in RFC 9497.
scalarReduce :: ByteString -> ByteString
scalarReduce wide
  | BS.length wide /= hashBytes = error "opaque: scalarReduce takes 64 bytes"
  | otherwise =
      unsafeDupablePerformIO . sodium $
        withBytes wide $
          \i _ -> fresh scalarBytes (`c_scalar_reduce` i)

-- | 'scalarInvert' is the inverse of a scalar modulo the group's order, or
-- 'Nothing' for zero.
scalarInvert :: ByteString -> Maybe ByteString
scalarInvert s = unsafeDupablePerformIO . sodium $
  withBytes s $
    \i _ -> freshOr scalarBytes (`c_scalar_invert` i)

-- | 'scalarMult' multiplies an encoded element by a scalar. It is
-- 'Nothing' when the element's encoding is not valid or the product is the
-- identity (a zero scalar).
scalarMult :: ByteString -> ByteString -> Maybe ByteString
scalarMult s e
  | BS.length s /= scalarBytes || BS.length e /= elementBytes = Nothing
  | otherwise =
      unsafeDupablePerformIO . sodium $
        withBytes s $ \sp _ -> withBytes e $ \ep _ ->
          freshOr elementBytes (\o -> c_scalarmult o sp ep)

-- | 'scalarMultBase' multiplies the group's generator by a scalar:
-- ScalarMultGen. It is 'Nothing' for a zero scalar.
scalarMultBase :: ByteString -> Maybe ByteString
scalarMultBase s
  | BS.length s /= scalarBytes = Nothing
  | otherwise =
      unsafeDupablePerformIO . sodium $
        withBytes s $
          \sp _ -> freshOr elementBytes (`c_scalarmult_base` sp)

-- | 'randomScalar' is a uniformly random non-zero scalar: RFC 9497's
-- RandomScalar.
randomScalar :: IO ByteString
randomScalar = sodium (fresh scalarBytes c_scalar_random)

-- | 'argon2id' stretches a message with Argon2id version 1.3 into 64 bytes,
-- with the given salt (16 bytes), number of passes and memory in bytes. It
-- is 'Nothing' when libsodium refuses: limits out of its range, or memory
-- that cannot be allocated.
argon2id :: Word64 -> Word64 -> ByteString -> ByteString -> Maybe ByteString
argon2id opsLimit memLimit salt msg
  | BS.length salt /= 16 = Nothing
  | otherwise = unsafePerformIO . sodium $ do
      alg <- c_pwhash_alg_argon2id13
      withBytes msg $ \m mn -> withBytes salt $ \s _ ->
        freshOr hashBytes $ \o ->
          c_pwhash
            o
            (fromIntegral hashBytes)
            m
            (fromIntegral mn)
            s
            (fromIntegral opsLimit)
            (fromIntegral memLimit)
            alg

-- | 'randomBytes' is @n@ bytes from the system's source of random numbers
-- (@getrandom@ natively, WASI's @random_get@ in the browser).
randomBytes :: Int -> IO ByteString
randomBytes n = sodium (fresh n (\p -> c_randombytes_buf (castPtr p) (fromIntegral n)))

-- | 'constantTimeEqual' compares two byte strings in time that depends only
-- on their length, so that a comparison of MACs tells an attacker nothing
-- about how many bytes were right. Strings of different lengths are not
-- equal.
constantTimeEqual :: ByteString -> ByteString -> Bool
constantTimeEqual a b
  | BS.length a /= BS.length b = False
  | otherwise =
      unsafeDupablePerformIO . sodium $
        withBytes a $ \pa n -> withBytes b $ \pb _ ->
          (== 0) <$> c_memcmp (castPtr pa) (castPtr pb) (fromIntegral n)
