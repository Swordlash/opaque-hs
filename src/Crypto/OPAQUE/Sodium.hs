-- | The libsodium functions the protocol is built from, and nothing else.
--
-- Every cryptographic primitive OPAQUE needs comes from libsodium: the
-- ristretto255 group (hash-to-group, scalars, scalar multiplication),
-- SHA-512, HMAC-SHA-512, Argon2id and the system's random numbers. This
-- module binds the C functions with @ccall@ imports. Nothing here
-- implements a primitive.
--
-- The functions whose names end in @Into@ write their result into memory
-- the caller gives, a 'Crypto.OPAQUE.Secret.Scratch' buffer or a
-- 'Crypto.OPAQUE.Secret.Secret', and read their inputs as 'Part's, so that
-- the protocol's secrets never become ordinary 'ByteString's. The
-- temporaries of each call (a hash's state) are zeroed before it returns.
-- The functions over 'ByteString's are for public values, and for the
-- tests.
module Crypto.OPAQUE.Sodium
  ( -- * Sizes
    elementBytes
  , scalarBytes
  , hashBytes

    -- * Inputs
  , Part (..)
  , partLength
  , withPart

    -- * Writing into memory
  , sha512Into
  , hmacSha512Into
  , fromHashInto
  , scalarReduceInto
  , scalarInvertInto
  , scalarMultInto
  , scalarMultBaseInto
  , scalarRandomInto
  , argon2idInto
  , randomInto
  , isZero
  , equalTo
  , publicBytes
  , publicBytesOr

    -- * Over 'ByteString's
  , sha512
  , hmacSha512
  , fromHash
  , isValidElement
  , scalarReduce
  , scalarInvert
  , scalarMult
  , scalarMultBase
  , randomScalar
  , argon2id
  , randomBytes
  , constantTimeEqual
  )
where

import Control.Exception (evaluate)
import Control.Monad (void)
import Crypto.OPAQUE.Secret (sodiumReady, withScrubbed)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CInt (..), CSize (..), CUChar, CULLong (..))
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)

foreign import ccall unsafe "crypto_hash_sha512_statebytes"
  c_sha512_statebytes :: IO CSize

foreign import ccall unsafe "crypto_hash_sha512_init"
  c_sha512_init :: Ptr () -> IO CInt

foreign import ccall unsafe "crypto_hash_sha512_update"
  c_sha512_update :: Ptr () -> Ptr CUChar -> CULLong -> IO CInt

foreign import ccall unsafe "crypto_hash_sha512_final"
  c_sha512_final :: Ptr () -> Ptr CUChar -> IO CInt

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

foreign import ccall unsafe "sodium_is_zero"
  c_is_zero :: Ptr CUChar -> CSize -> IO CInt

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

-- | Run a libsodium call after the library is initialised.
sodium :: IO a -> IO a
sodium act = evaluate sodiumReady >> act

-- | 'Part' is one input to a hash, a MAC or a group operation: public bytes,
-- or bytes of secret memory, given by their address and length.
data Part
  = Pub ByteString
  | Mem (Ptr Word8) Int

-- | The length of a part in bytes.
partLength :: Part -> Int
partLength (Pub bs) = BS.length bs
partLength (Mem _ n) = n

-- | 'withPart' runs an action with a part's address and length.
withPart :: Part -> (Ptr CUChar -> Int -> IO a) -> IO a
withPart (Pub bs) f = unsafeUseAsCStringLen bs (\(p, n) -> f (castPtr p) n)
withPart (Mem p n) f = f (castPtr p) n

-- | Feed every part to a streaming update function.
feed :: (Ptr CUChar -> CULLong -> IO CInt) -> [Part] -> IO ()
feed update = mapM_ (\part -> withPart part (\p n -> void (update p (fromIntegral n))))

-- | The size of libsodium's SHA-512 state, asked of the library once.
sha512StateBytes :: Int
sha512StateBytes = fromIntegral (unsafePerformIO c_sha512_statebytes)
{-# NOINLINE sha512StateBytes #-}

-- | The size of libsodium's HMAC-SHA-512 state, asked of the library once.
hmacStateBytes :: Int
hmacStateBytes = fromIntegral (unsafePerformIO c_hmacsha512_statebytes)
{-# NOINLINE hmacStateBytes #-}

-- | 'sha512Into' writes SHA-512 of the concatenation of the parts, 64
-- bytes. The state is zeroed afterwards.
sha512Into :: Ptr Word8 -> [Part] -> IO ()
sha512Into out parts = sodium $
  withScrubbed sha512StateBytes $ \st -> do
    _ <- c_sha512_init (castPtr st)
    feed (c_sha512_update (castPtr st)) parts
    void (c_sha512_final (castPtr st) (castPtr out))

-- | 'hmacSha512Into' writes HMAC-SHA-512 with a key of any length over the
-- concatenation of the parts, 64 bytes. It goes through the streaming
-- interface because libsodium's one-shot @crypto_auth_hmacsha512@ takes a
-- key of exactly 32 bytes, and OPAQUE's keys are 64. The state, which holds
-- the key, is zeroed afterwards. The output may be the memory of one of the
-- parts: the parts are read before it is written.
hmacSha512Into :: Ptr Word8 -> Part -> [Part] -> IO ()
hmacSha512Into out key parts = sodium $
  withScrubbed hmacStateBytes $ \st ->
    withPart key $ \k kn -> do
      _ <- c_hmacsha512_init (castPtr st) k (fromIntegral kn)
      feed (c_hmacsha512_update (castPtr st)) parts
      void (c_hmacsha512_final (castPtr st) (castPtr out))

-- | 'fromHashInto' maps 64 uniformly random bytes to a ristretto255
-- element: the one-way map of RFC 9496, which @hash_to_ristretto255@ of RFC
-- 9380 applies to the output of @expand_message_xmd@.
fromHashInto :: Ptr Word8 -> Ptr Word8 -> IO ()
fromHashInto out h = sodium (void (c_from_hash (castPtr out) (castPtr h)))

-- | 'scalarReduceInto' reads 64 bytes as a little-endian integer and
-- reduces it modulo the group's order: HashToScalar's last step in RFC
-- 9497.
scalarReduceInto :: Ptr Word8 -> Ptr Word8 -> IO ()
scalarReduceInto out wide = sodium (c_scalar_reduce (castPtr out) (castPtr wide))

-- | 'scalarInvertInto' writes the inverse of a scalar modulo the group's
-- order. It is 'False' for zero.
scalarInvertInto :: Ptr Word8 -> Ptr Word8 -> IO Bool
scalarInvertInto out s = sodium ((== 0) <$> c_scalar_invert (castPtr out) (castPtr s))

-- | 'scalarMultInto' multiplies an encoded element by a scalar. It is
-- 'False' when the element's encoding is not valid or the product is the
-- identity (a zero scalar).
scalarMultInto :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO Bool
scalarMultInto out s e = sodium ((== 0) <$> c_scalarmult (castPtr out) (castPtr s) (castPtr e))

-- | 'scalarMultBaseInto' multiplies the group's generator by a scalar:
-- ScalarMultGen. It is 'False' for a zero scalar.
scalarMultBaseInto :: Ptr Word8 -> Ptr Word8 -> IO Bool
scalarMultBaseInto out s = sodium ((== 0) <$> c_scalarmult_base (castPtr out) (castPtr s))

-- | 'scalarRandomInto' writes a uniformly random non-zero scalar: RFC
-- 9497's RandomScalar.
scalarRandomInto :: Ptr Word8 -> IO ()
scalarRandomInto out = sodium (c_scalar_random (castPtr out))

-- | 'argon2idInto' stretches a message with Argon2id version 1.3 into 64
-- bytes, with the given salt (16 bytes), number of passes and memory in
-- bytes. It is 'False' when libsodium refuses: limits out of its range, a
-- salt of another length, or memory that cannot be allocated. libsodium
-- zeroes its own working memory.
argon2idInto :: Ptr Word8 -> ByteString -> Part -> Word64 -> Word64 -> IO Bool
argon2idInto out salt msg opsLimit memLimit
  | BS.length salt /= 16 = pure False
  | otherwise = sodium $ do
      alg <- c_pwhash_alg_argon2id13
      withPart msg $ \m mn -> withPart (Pub salt) $ \s _ ->
        (== 0)
          <$> c_pwhash
            (castPtr out)
            (fromIntegral hashBytes)
            m
            (fromIntegral mn)
            s
            (fromIntegral opsLimit)
            (fromIntegral memLimit)
            alg

-- | 'randomInto' writes @n@ bytes from the system's source of random
-- numbers (@getrandom@ natively, WASI's @random_get@ in the browser).
randomInto :: Ptr Word8 -> Int -> IO ()
randomInto out n = sodium (c_randombytes_buf (castPtr out) (fromIntegral n))

-- | Whether @n@ bytes are all zero, in time that depends only on @n@.
isZero :: Ptr Word8 -> Int -> IO Bool
isZero p n = sodium ((== 1) <$> c_is_zero (castPtr p) (fromIntegral n))

-- | 'equalTo' compares public bytes with memory of the same length in time
-- that depends only on the length, so that a comparison of MACs tells an
-- attacker nothing about how many bytes were right. Bytes of another
-- length are not equal.
equalTo :: ByteString -> Ptr Word8 -> Int -> IO Bool
equalTo bs p n
  | BS.length bs /= n = pure False
  | otherwise =
      sodium $
        unsafeUseAsCStringLen bs $ \(q, _) ->
          (== 0) <$> c_memcmp (castPtr q) (castPtr p) (fromIntegral n)

-- | 'publicBytes' makes a 'ByteString' of @n@ bytes with the action, for a
-- value that is public (a message, a public key, a MAC that is sent). The
-- bytes are made and evaluated before it returns.
publicBytes :: Int -> (Ptr Word8 -> IO ()) -> IO ByteString
publicBytes = BSI.create

-- | 'publicBytesOr' is 'publicBytes' for an action that can fail.
publicBytesOr :: Int -> (Ptr Word8 -> IO Bool) -> IO (Maybe ByteString)
publicBytesOr n f = do
  (bs, ok) <- BSI.createUptoN' n (\p -> f p >>= \ok -> pure (if ok then n else 0, ok))
  pure (if ok then Just bs else Nothing)

-- | Read public bytes as an input of exactly @n@ bytes, or give 'Nothing'.
withExactly :: Int -> ByteString -> (Ptr Word8 -> IO (Maybe a)) -> IO (Maybe a)
withExactly n bs f
  | BS.length bs /= n = pure Nothing
  | otherwise = unsafeUseAsCStringLen bs (\(p, _) -> f (castPtr p))

-- | 'sha512' is SHA-512 over the concatenation of the parts.
sha512 :: [ByteString] -> ByteString
sha512 parts = unsafeDupablePerformIO (publicBytes hashBytes (\o -> sha512Into o (map Pub parts)))

-- | 'hmacSha512' is HMAC-SHA-512 with a key of any length over the
-- concatenation of the parts.
hmacSha512 :: ByteString -> [ByteString] -> ByteString
hmacSha512 key parts = unsafeDupablePerformIO (publicBytes hashBytes (\o -> hmacSha512Into o (Pub key) (map Pub parts)))

-- | 'fromHash' is 'fromHashInto' over bytes.
fromHash :: ByteString -> ByteString
fromHash h =
  maybe (error "opaque: fromHash takes 64 bytes") id . unsafeDupablePerformIO $
    withExactly hashBytes h (\i -> Just <$> publicBytes elementBytes (`fromHashInto` i))

-- | 'isValidElement' says whether the bytes are the canonical encoding of a
-- ristretto255 element other than the identity. libsodium's check accepts
-- the identity (32 zero bytes), which RFC 9497's DeserializeElement must
-- refuse, so the identity is refused here as well.
isValidElement :: ByteString -> Bool
isValidElement e =
  BS.length e == elementBytes
    && BS.any (/= 0) e
    && unsafeDupablePerformIO (sodium (withPart (Pub e) (\p _ -> (== 1) <$> c_is_valid_point p)))

-- | 'scalarReduce' is 'scalarReduceInto' over bytes.
scalarReduce :: ByteString -> ByteString
scalarReduce wide =
  maybe (error "opaque: scalarReduce takes 64 bytes") id . unsafeDupablePerformIO $
    withExactly hashBytes wide (\i -> Just <$> publicBytes scalarBytes (`scalarReduceInto` i))

-- | 'scalarInvert' is 'scalarInvertInto' over bytes: 'Nothing' for zero or
-- a scalar of the wrong length.
scalarInvert :: ByteString -> Maybe ByteString
scalarInvert s = unsafeDupablePerformIO $ withExactly scalarBytes s (publicBytesOr scalarBytes . flip scalarInvertInto)

-- | 'scalarMult' is 'scalarMultInto' over bytes: 'Nothing' for an invalid
-- element, a zero scalar, or either of the wrong length.
scalarMult :: ByteString -> ByteString -> Maybe ByteString
scalarMult s e = unsafeDupablePerformIO $
  withExactly scalarBytes s $ \sp -> withExactly elementBytes e $ \ep ->
    publicBytesOr elementBytes (\o -> scalarMultInto o sp ep)

-- | 'scalarMultBase' is 'scalarMultBaseInto' over bytes: 'Nothing' for a
-- zero scalar or one of the wrong length.
scalarMultBase :: ByteString -> Maybe ByteString
scalarMultBase s = unsafeDupablePerformIO $ withExactly scalarBytes s (publicBytesOr elementBytes . flip scalarMultBaseInto)

-- | 'randomScalar' is a random non-zero scalar as bytes, for tests.
randomScalar :: IO ByteString
randomScalar = publicBytes scalarBytes scalarRandomInto

-- | 'argon2id' is 'argon2idInto' over bytes, with the salt given (16 bytes).
argon2id :: Word64 -> Word64 -> ByteString -> ByteString -> Maybe ByteString
argon2id opsLimit memLimit salt msg =
  unsafePerformIO (publicBytesOr hashBytes (\o -> argon2idInto o salt (Pub msg) opsLimit memLimit))

-- | 'randomBytes' is @n@ random bytes, for public values: nonces.
randomBytes :: Int -> IO ByteString
randomBytes n = publicBytes n (`randomInto` n)

-- | 'constantTimeEqual' compares two byte strings in time that depends only
-- on their length. Strings of different lengths are not equal.
constantTimeEqual :: ByteString -> ByteString -> Bool
constantTimeEqual a b = unsafeDupablePerformIO (withPart (Pub b) (\p n -> equalTo a (castPtr p) n))
