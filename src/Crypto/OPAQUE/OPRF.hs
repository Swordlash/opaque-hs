-- | The oblivious pseudorandom function of RFC 9497 in its OPRF mode
-- (@modeOPRF@) over ristretto255 with SHA-512: the suite
-- @ristretto255-SHA512@.
--
-- An OPRF lets a client compute a function of its secret input under the
-- server's secret key, while the server learns nothing of the input and the
-- client nothing of the key. The client blinds its input with a random
-- scalar ('blindInto'), the server multiplies the blinded element by its
-- key ('blindEvaluateWith'), and the client removes the blind and hashes the
-- result ('finalizeInto'). OPAQUE runs it on the password, so that the
-- password becomes a strong secret only with the server's help.
--
-- Elements and scalars are their encodings, 32 bytes each. The functions
-- whose names end in @Into@ or @With@ read secrets (the input, the blind,
-- the key) from memory and write secrets into memory; their temporaries
-- (the input's element, the inverse of the blind, the unblinded element) are
-- zeroed before they return. The functions over 'ByteString's are for the
-- RFC's test vectors.
module Crypto.OPAQUE.OPRF
  ( contextString
  , maxInputBytes
  , hashToGroupInto
  , hashToScalarInto
  , deriveKeyPairInto
  , blindInto
  , blindEvaluateWith
  , finalizeInto

    -- * Over 'ByteString's, for the test vectors
  , hashToGroup
  , hashToScalar
  , deriveKeyPair
  , blindWith
  , blindEvaluate
  , finalize
  , evaluate
  )
where

import Crypto.OPAQUE.Kdf (expandMessageXmdInto, i2osp)
import Crypto.OPAQUE.Secret (withScrubbed)
import Crypto.OPAQUE.Sodium
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word8)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

-- | 'contextString' is RFC 9497's context string for @modeOPRF@ (the byte
-- 0) and the suite @ristretto255-SHA512@. It separates this suite's hashes
-- from every other use of the same hash functions.
contextString :: ByteString
contextString = "OPRFV1-" <> BS.singleton 0 <> "-ristretto255-SHA512"

-- | The longest input this package takes: 65534 bytes. RFC 9497, section
-- 5.1, says an input "MUST be smaller than 2^16 - 1 bytes"; the two-byte
-- length in Finalize's hash could say 65535, but the RFC keeps one below.
maxInputBytes :: Int
maxInputBytes = 65534

-- | 'hashToGroupInto' maps the input to a group element, 32 bytes at
-- @out@: @hash_to_ristretto255@ of RFC 9380, with the domain separation tag
-- RFC 9497 gives this suite.
hashToGroupInto :: Ptr Word8 -> [Part] -> IO ()
hashToGroupInto out msg =
  withScrubbed hashBytes $ \uniform -> do
    expandMessageXmdInto uniform hashBytes msg ("HashToGroup-" <> contextString)
    fromHashInto out uniform

-- | 'hashToScalarInto' maps the input to a scalar under a domain separation
-- tag: 64 bytes of @expand_message_xmd@ reduced modulo the group's order.
hashToScalarInto :: Ptr Word8 -> ByteString -> [Part] -> IO ()
hashToScalarInto out dst msg =
  withScrubbed hashBytes $ \uniform -> do
    expandMessageXmdInto uniform hashBytes msg dst
    scalarReduceInto out uniform

-- | 'deriveKeyPairInto' is RFC 9497's DeriveKeyPair: a private scalar,
-- written at @sk@, and its public element, returned, from a seed and a
-- public info string. A counter is appended and incremented while the
-- scalar is zero, which happens with negligible probability; after 256
-- tries it gives up ('Nothing', the RFC's DeriveKeyPairError).
deriveKeyPairInto :: Ptr Word8 -> [Part] -> ByteString -> IO (Maybe ByteString)
deriveKeyPairInto sk seed info = go 0
  where
    go counter
      | counter > (255 :: Int) = pure Nothing
      | otherwise = do
          hashToScalarInto sk ("DeriveKeyPair" <> contextString) (seed <> [Pub (i2osp 2 (BS.length info) <> info <> i2osp 1 counter)])
          zero <- isZero sk scalarBytes
          if zero
            then go (counter + 1)
            else publicBytesOr elementBytes (`scalarMultBaseInto` sk)

-- | 'blindInto' is RFC 9497's Blind with the blind (32 bytes at @r@)
-- given: the blinded element, which the client sends. 'Nothing' is the
-- RFC's InvalidInputError: an input longer than 'maxInputBytes', a zero
-- blind, or an input that hashes to the identity (negligible probability).
blindInto :: Ptr Word8 -> Part -> IO (Maybe ByteString)
blindInto r input
  | partLength input > maxInputBytes = pure Nothing
  | otherwise =
      withScrubbed elementBytes $ \element -> do
        hashToGroupInto element [input]
        publicBytesOr elementBytes (\o -> scalarMultInto o r element)

-- | 'blindEvaluateWith' is RFC 9497's BlindEvaluate: the server multiplies
-- the client's blinded element by its private key (32 bytes at @k@).
-- 'Nothing' means the element was not valid.
blindEvaluateWith :: Ptr Word8 -> ByteString -> IO (Maybe ByteString)
blindEvaluateWith k blinded
  | BS.length blinded /= elementBytes = pure Nothing
  | otherwise =
      unsafeUseAsCStringLen blinded $ \(b, _) ->
        publicBytesOr elementBytes (\o -> scalarMultInto o k (castPtr b))

-- | 'finalizeInto' is RFC 9497's Finalize: the client removes its blind (32
-- bytes at @r@) from the server's evaluated element and hashes the input
-- with the result, 64 bytes at @out@. 'False' means the input was too long,
-- or the blind or the element was not valid.
finalizeInto :: Ptr Word8 -> Part -> Ptr Word8 -> ByteString -> IO Bool
finalizeInto out input r evaluated
  | partLength input > maxInputBytes || BS.length evaluated /= elementBytes = pure False
  | otherwise =
      withScrubbed (scalarBytes + elementBytes) $ \buf -> do
        let inverse = buf
            unblinded = buf `plusPtr` scalarBytes
        inverted <- scalarInvertInto inverse r
        multiplied <-
          if inverted
            then unsafeUseAsCStringLen evaluated (\(e, _) -> scalarMultInto unblinded inverse (castPtr e))
            else pure False
        if multiplied
          then True <$ finalHashInto out input unblinded
          else pure False

-- | The hash that ends Finalize and Evaluate.
finalHashInto :: Ptr Word8 -> Part -> Ptr Word8 -> IO ()
finalHashInto out input element =
  sha512Into
    out
    [ Pub (i2osp 2 (partLength input))
    , input
    , Pub (i2osp 2 elementBytes)
    , Mem element elementBytes
    , Pub "Finalize"
    ]

-- | 'hashToGroup' is 'hashToGroupInto' over bytes.
hashToGroup :: ByteString -> ByteString
hashToGroup x = unsafePerformIO (publicBytes elementBytes (\o -> hashToGroupInto o [Pub x]))

-- | 'hashToScalar' is 'hashToScalarInto' over bytes.
hashToScalar :: ByteString -> ByteString -> ByteString
hashToScalar dst x = unsafePerformIO (publicBytes scalarBytes (\o -> hashToScalarInto o dst [Pub x]))

-- | 'deriveKeyPair' is 'deriveKeyPairInto' over bytes: the private scalar
-- and the public element.
deriveKeyPair :: ByteString -> ByteString -> Maybe (ByteString, ByteString)
deriveKeyPair seed info = unsafePerformIO $ do
  (sk, pk) <- BSI.createAndTrim' scalarBytes (\o -> (,,) 0 scalarBytes <$> deriveKeyPairInto o [Pub seed] info)
  pure ((,) sk <$> pk)

-- | 'blindWith' is 'blindInto' over bytes: the blind and the blinded
-- element.
blindWith :: ByteString -> ByteString -> Maybe (ByteString, ByteString)
blindWith r input
  | BS.length r /= scalarBytes = Nothing
  | otherwise = unsafePerformIO $ unsafeUseAsCStringLen r $ \(rp, _) ->
      fmap ((,) r) <$> blindInto (castPtr rp) (Pub input)

-- | 'blindEvaluate' is 'blindEvaluateWith' over bytes.
blindEvaluate :: ByteString -> ByteString -> Maybe ByteString
blindEvaluate k blinded
  | BS.length k /= scalarBytes = Nothing
  | otherwise = unsafePerformIO $ unsafeUseAsCStringLen k (\(kp, _) -> blindEvaluateWith (castPtr kp) blinded)

-- | 'finalize' is 'finalizeInto' over bytes: the output, 64 bytes.
finalize :: ByteString -> ByteString -> ByteString -> Maybe ByteString
finalize input r evaluated
  | BS.length r /= scalarBytes = Nothing
  | otherwise = unsafePerformIO $ unsafeUseAsCStringLen r $ \(rp, _) ->
      publicBytesOr hashBytes (\o -> finalizeInto o (Pub input) (castPtr rp) evaluated)

-- | 'evaluate' is RFC 9497's Evaluate: the same output as the protocol,
-- computed by someone who knows both the key and the input.
evaluate :: ByteString -> ByteString -> Maybe ByteString
evaluate k input
  | BS.length k /= scalarBytes || BS.length input > maxInputBytes = Nothing
  | otherwise = unsafePerformIO $ unsafeUseAsCStringLen k $ \(kp, _) ->
      withScrubbed (2 * elementBytes) $ \buf -> do
        let element = buf
            evaluated = buf `plusPtr` elementBytes
        hashToGroupInto element [Pub input]
        publicBytesOr hashBytes $ \o -> do
          ok <- scalarMultInto evaluated (castPtr kp) element
          if ok then True <$ finalHashInto o (Pub input) evaluated else pure False
