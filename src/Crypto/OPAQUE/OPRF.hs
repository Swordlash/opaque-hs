-- | The oblivious pseudorandom function of RFC 9497 in its OPRF mode
-- (@modeOPRF@) over ristretto255 with SHA-512: the suite
-- @ristretto255-SHA512@.
--
-- An OPRF lets a client compute a function of its secret input under the
-- server's secret key, while the server learns nothing of the input and the
-- client nothing of the key. The client blinds its input with a random
-- scalar ('blind'), the server multiplies the blinded element by its key
-- ('blindEvaluate'), and the client removes the blind and hashes the result
-- ('finalize'). OPAQUE runs it on the password, so that the password
-- becomes a strong secret only with the server's help.
--
-- Elements and scalars are their encodings, 32 bytes each. The functions
-- that take a random value from the caller exist for the RFC's test
-- vectors; 'blind' takes it from libsodium.
module Crypto.OPAQUE.OPRF
  ( contextString
  , hashToGroup
  , hashToScalar
  , deriveKeyPair
  , blind
  , blindWith
  , blindEvaluate
  , finalize
  , evaluate
  )
where

import Control.Monad (guard)
import Crypto.OPAQUE.Kdf (expandMessageXmd, i2osp)
import Crypto.OPAQUE.Sodium
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS

-- | 'contextString' is RFC 9497's context string for @modeOPRF@ (the byte
-- 0) and the suite @ristretto255-SHA512@. It separates this suite's hashes
-- from every other use of the same hash functions.
contextString :: ByteString
contextString = "OPRFV1-" <> BS.singleton 0 <> "-ristretto255-SHA512"

-- | 'hashToGroup' maps bytes to a group element: @hash_to_ristretto255@ of
-- RFC 9380, with the domain separation tag RFC 9497 gives this suite.
hashToGroup :: ByteString -> ByteString
hashToGroup x = fromHash (expandMessageXmd x ("HashToGroup-" <> contextString) 64)

-- | 'hashToScalar' maps bytes to a scalar under a domain separation tag:
-- 64 bytes of @expand_message_xmd@ reduced modulo the group's order.
hashToScalar :: ByteString -> ByteString -> ByteString
hashToScalar dst x = scalarReduce (expandMessageXmd x dst 64)

-- | 'deriveKeyPair' is RFC 9497's DeriveKeyPair: a private scalar and its
-- public element, derived from a 32-byte seed and a public info string. A
-- counter is appended and incremented while the scalar is zero, which
-- happens with negligible probability; after 256 tries it gives up
-- ('Nothing', the RFC's DeriveKeyPairError).
deriveKeyPair :: ByteString -> ByteString -> Maybe (ByteString, ByteString)
deriveKeyPair seed info = go 0
  where
    deriveInput = seed <> i2osp 2 (BS.length info) <> info
    go counter
      | counter > (255 :: Int) = Nothing
      | otherwise =
          let sk = hashToScalar ("DeriveKeyPair" <> contextString) (deriveInput <> i2osp 1 counter)
           in case scalarMultBase sk of
                Just pk | BS.any (/= 0) sk -> Just (sk, pk)
                _ -> go (counter + 1)

-- | 'blind' is RFC 9497's Blind with a random blind from libsodium. It
-- returns the blind, which the client keeps, and the blinded element, which
-- it sends. 'Nothing' is the RFC's InvalidInputError: the input hashes to
-- the identity, which happens with negligible probability.
blind :: ByteString -> IO (Maybe (ByteString, ByteString))
blind input = (`blindWith` input) <$> randomScalar

-- | 'blindWith' is 'blind' with the blind given, for test vectors.
blindWith :: ByteString -> ByteString -> Maybe (ByteString, ByteString)
blindWith r input = do
  guard (fitting input)
  blinded <- scalarMult r (hashToGroup input)
  pure (r, blinded)

-- | 'blindEvaluate' is RFC 9497's BlindEvaluate: the server multiplies the
-- client's blinded element by its private key. The element must have been
-- checked with 'isValidElement'; 'Nothing' means it was not valid.
blindEvaluate :: ByteString -> ByteString -> Maybe ByteString
blindEvaluate = scalarMult

-- | 'finalize' is RFC 9497's Finalize: the client removes its blind from
-- the server's evaluated element and hashes the input with the result. The
-- output is 64 bytes. 'Nothing' means the blind or the element was not
-- valid.
finalize :: ByteString -> ByteString -> ByteString -> Maybe ByteString
finalize input r evaluated = do
  guard (fitting input)
  inverse <- scalarInvert r
  unblinded <- scalarMult inverse evaluated
  pure (finalHash input unblinded)

-- | 'evaluate' is RFC 9497's Evaluate: the same output as the protocol,
-- computed by someone who knows both the key and the input.
evaluate :: ByteString -> ByteString -> Maybe ByteString
evaluate sk input = do
  guard (fitting input)
  finalHash input <$> scalarMult sk (hashToGroup input)

-- | Whether an input is one RFC 9497 takes (section 5.1): smaller than
-- 65535 bytes, so that its two-byte length in Finalize's hash cannot wrap.
fitting :: ByteString -> Bool
fitting input = BS.length input < 65535

-- | The hash that ends Finalize and Evaluate.
finalHash :: ByteString -> ByteString -> ByteString
finalHash input element =
  sha512
    [ i2osp 2 (BS.length input)
    , input
    , i2osp 2 (BS.length element)
    , element
    , "Finalize"
    ]
