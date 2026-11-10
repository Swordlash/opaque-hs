{-# LANGUAGE ForeignFunctionInterface #-}

-- | The reference implementation's steps, as the tests call them: libopaque
-- (and the liboprf it is written over), built by @scripts/reference.sh@ and
-- called through @cbits/shim.c@.
--
-- A step that draws random values takes a 'Script': the values it is to
-- draw, in the order it draws them, or 'Real' for libsodium's own random
-- bytes. The shim fails the step when the script does not fit (it asked
-- for more, or less, than the script has), so a comparison never runs on
-- inputs the two sides do not share.
--
-- Messages and keys are their bytes, as libopaque writes them: the layouts
-- of RFC 9807 (KE1, KE2, the registration's messages and the record). What
-- libopaque keeps between two steps (its secrets) is passed back to it
-- unread.
module Reference
  ( install
  , Script (..)
  , Ids (..)

    -- * Registration
  , registrationRequest
  , registrationResponse
  , finalizeRegistration
  , storeRecord

    -- * Login
  , clientStart
  , ServerAnswer (..)
  , serverRespond
  , ClientEnd (..)
  , clientFinish
  , serverFinish

    -- * liboprf's functions
  , hashToGroup
  , evaluate
  , unblind
  , finalize
  , expandMessageXmd
  )
where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Word (Word16, Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)

-- | 'Script' is the random values a step draws.
data Script
  = -- | These values, each drawn whole, in this order.
    Scripted [ByteString]
  | -- | libsodium's own random bytes.
    Real

-- | 'Ids' are the two parties' identities, as libopaque takes them: no
-- bytes is no identity, which stands for the party's public key.
data Ids = Ids
  { client :: ByteString
  , server :: ByteString
  }

foreign import ccall unsafe "ref_install" c_install :: IO CInt

foreign import ccall unsafe "ref_registration_secret_len" c_registration_secret_len :: Word16 -> CSize

foreign import ccall unsafe "ref_login_secret_len" c_login_secret_len :: Word16 -> CSize

foreign import ccall unsafe "ref_server_secret_len" c_server_secret_len :: CSize

foreign import ccall unsafe "ref_registration_response_len" c_registration_response_len :: CSize

foreign import ccall unsafe "ref_registration_record_len" c_registration_record_len :: CSize

foreign import ccall unsafe "ref_user_record_len" c_user_record_len :: CSize

foreign import ccall unsafe "ref_ke1_len" c_ke1_len :: CSize

foreign import ccall unsafe "ref_ke2_len" c_ke2_len :: CSize

foreign import ccall unsafe "ref_registration_request"
  c_registration_request :: Ptr Word8 -> CSize -> Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_registration_response"
  c_registration_response :: Ptr Word8 -> CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_finalize_registration"
  c_finalize_registration :: Ptr Word8 -> CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_store_record"
  c_store_record :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "ref_client_start"
  c_client_start :: Ptr Word8 -> CSize -> Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_server_respond"
  c_server_respond :: Ptr Word8 -> CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_client_finish"
  c_client_finish :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ref_server_finish"
  c_server_finish :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "voprf_hash_to_group"
  c_hash_to_group :: Ptr Word8 -> Word16 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "oprf_Evaluate"
  c_evaluate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "oprf_Unblind"
  c_unblind :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "oprf_Finalize"
  c_finalize :: Ptr Word8 -> Word16 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "oprf_expand_message_xmd"
  c_expand_message_xmd :: Ptr Word8 -> Word16 -> Ptr Word8 -> Word8 -> Word8 -> Ptr Word8 -> IO CInt

-- | Make libsodium take its random bytes through the shim. Once, before
-- anything else uses libsodium.
install :: IO ()
install = do
  r <- c_install
  if r == 0 then pure () else ioError (userError "the reference's source of random bytes could not be installed")

-- | Some bytes as a pointer and a length, for the length of the call.
bytes :: ByteString -> (Ptr Word8 -> Int -> IO a) -> IO a
bytes b act = unsafeUseAsCStringLen b (\(p, n) -> act (castPtr p) n)

-- | A script as the shim takes it: the values one after another, or no
-- pointer for real random bytes.
scripted :: Script -> (Ptr Word8 -> CSize -> IO a) -> IO a
scripted s act = case s of
  Real -> act nullPtr 0
  Scripted values -> bytes (BS.concat values) (\p n -> act p (fromIntegral n))

-- | Run a step that writes its results into buffers of these lengths:
-- the results, or the step's failure code.
into :: [Int] -> ([Ptr Word8] -> IO CInt) -> IO (Either Int [ByteString])
into lengths step = go lengths []
  where
    go [] made = do
      let outs = reverse made
      r <- step (map fst outs)
      if r == 0
        then Right <$> traverse (\(p, n) -> BS.packCStringLen (castPtr p, n)) outs
        else pure (Left (fromIntegral r))
    go (n : more) made = allocaBytes (max 1 n) (\p -> go more ((p, n) : made))

size :: CSize -> Int
size = fromIntegral

len16 :: Int -> Word16
len16 = fromIntegral

-- | CreateRegistrationRequest. Draws the blind. Gives libopaque's secret
-- for 'finalizeRegistration', and the request.
registrationRequest :: Script -> ByteString -> IO (Either Int (ByteString, ByteString))
registrationRequest script password =
  scripted script $ \sp sn -> bytes password $ \pp pn ->
    pair
      <$> into
        [size (c_registration_secret_len (len16 pn)), 32]
        ( \outs -> case outs of
            [secret, request] -> c_registration_request sp sn pp (len16 pn) secret request
            _ -> pure (-1)
        )

-- | CreateRegistrationResponse, with the server's private key. Draws the
-- client's OPRF key. Gives the server's secret for 'storeRecord', and the
-- response.
registrationResponse :: Script -> ByteString -> ByteString -> IO (Either Int (ByteString, ByteString))
registrationResponse script request serverPrivateKey =
  scripted script $ \sp sn -> bytes request $ \rp _ -> bytes serverPrivateKey $ \kp _ ->
    pair
      <$> into
        [size c_server_secret_len, size c_registration_response_len]
        ( \outs -> case outs of
            [secret, response] -> c_registration_response sp sn rp kp secret response
            _ -> pure (-1)
        )

-- | FinalizeRegistrationRequest. Draws the envelope's nonce. Gives the
-- registration record and the export key.
finalizeRegistration :: Script -> ByteString -> ByteString -> Ids -> IO (Either Int (ByteString, ByteString))
finalizeRegistration script secret response ids =
  scripted script $ \sp sn -> bytes secret $ \cp _ -> bytes response $ \rp _ ->
    bytes ids.client $ \ip il -> bytes ids.server $ \jp jl ->
      pair
        <$> into
          [size c_registration_record_len, 64]
          ( \outs -> case outs of
              [record, exportKey] -> c_finalize_registration sp sn cp rp ip (len16 il) jp (len16 jl) record exportKey
              _ -> pure (-1)
          )

-- | What libopaque's server stores for a client: its secret of the
-- registration, then the client's record.
storeRecord :: ByteString -> ByteString -> IO ByteString
storeRecord serverSecret record =
  bytes serverSecret $ \sp _ -> bytes record $ \rp _ ->
    allocaBytes (size c_user_record_len) $ \out -> do
      c_store_record sp rp out
      BS.packCStringLen (castPtr out, size c_user_record_len)

-- | GenerateKE1. Draws the blind, the seed of the client's key share and
-- its nonce, in that order. Gives libopaque's secret for 'clientFinish',
-- and KE1.
clientStart :: Script -> ByteString -> IO (Either Int (ByteString, ByteString))
clientStart script password =
  scripted script $ \sp sn -> bytes password $ \pp pn ->
    pair
      <$> into
        [size (c_login_secret_len (len16 pn)), size c_ke1_len]
        ( \outs -> case outs of
            [secret, ke1] -> c_client_start sp sn pp (len16 pn) secret ke1
            _ -> pure (-1)
        )

-- | 'ServerAnswer' is what libopaque's server makes of a KE1: KE2, its
-- session key, and the MAC it expects in KE3.
data ServerAnswer = ServerAnswer
  { ke2 :: ByteString
  , sessionKey :: ByteString
  , expectedMac :: ByteString
  }

-- | GenerateKE2, from KE1, the stored record ('storeRecord'), the
-- identities and the context. Draws the masking nonce, the server's nonce
-- and the seed of its key share, in that order.
serverRespond :: Script -> ByteString -> ByteString -> Ids -> ByteString -> IO (Either Int ServerAnswer)
serverRespond script ke1 userRecord ids context =
  scripted script $ \sp sn -> bytes ke1 $ \kp _ -> bytes userRecord $ \rp _ ->
    bytes ids.client $ \ip il -> bytes ids.server $ \jp jl -> bytes context $ \cp cl ->
      fmap answer
        <$> into
          [size c_ke2_len, 64, 64]
          ( \outs -> case outs of
              [ke2', sk, mac] -> c_server_respond sp sn kp rp ip (len16 il) jp (len16 jl) cp (len16 cl) ke2' sk mac
              _ -> pure (-1)
          )
  where
    answer = \case
      [ke2', sk, mac] -> ServerAnswer {ke2 = ke2', sessionKey = sk, expectedMac = mac}
      _ -> ServerAnswer BS.empty BS.empty BS.empty

-- | 'ClientEnd' is what libopaque's client makes of a KE2: its session
-- key, its MAC (KE3) and its export key.
data ClientEnd = ClientEnd
  { sessionKey :: ByteString
  , mac :: ByteString
  , exportKey :: ByteString
  }

-- | GenerateKE3, from KE2, the client's secret ('clientStart'), the
-- identities and the context. Draws nothing. Fails (a 'Left') when the
-- password is wrong or the server's MAC is.
clientFinish :: ByteString -> ByteString -> Ids -> ByteString -> IO (Either Int ClientEnd)
clientFinish ke2' secret ids context =
  bytes ke2' $ \kp _ -> bytes secret $ \sp _ ->
    bytes ids.client $ \ip il -> bytes ids.server $ \jp jl -> bytes context $ \cp cl ->
      fmap end
        <$> into
          [64, 64, 64]
          ( \outs -> case outs of
              [sk, mac', exportKey'] -> c_client_finish kp sp ip (len16 il) jp (len16 jl) cp (len16 cl) sk mac' exportKey'
              _ -> pure (-1)
          )
  where
    end = \case
      [sk, mac', exportKey'] -> ClientEnd {sessionKey = sk, mac = mac', exportKey = exportKey'}
      _ -> ClientEnd BS.empty BS.empty BS.empty

-- | ServerFinish: whether the client's MAC is the one the server expects.
serverFinish :: ByteString -> ByteString -> IO Bool
serverFinish expected mac' = bytes expected (\ep _ -> bytes mac' (\mp _ -> (== 0) <$> c_server_finish ep mp))

pair :: Either Int [ByteString] -> Either Int (ByteString, ByteString)
pair = \case
  Right [a, b] -> Right (a, b)
  Right _ -> Left (-1)
  Left e -> Left e

one :: Either Int [ByteString] -> Maybe ByteString
one = \case
  Right [a] -> Just a
  _ -> Nothing

-- | liboprf's HashToGroup of an input.
hashToGroup :: ByteString -> IO (Maybe ByteString)
hashToGroup input =
  bytes input $ \ip il ->
    one
      <$> into
        [32]
        ( \outs -> case outs of
            [out] -> c_hash_to_group ip (len16 il) out
            _ -> pure (-1)
        )

-- | liboprf's BlindEvaluate: a blinded element under a key.
evaluate :: ByteString -> ByteString -> IO (Maybe ByteString)
evaluate key blinded =
  bytes key $ \kp _ -> bytes blinded $ \bp _ ->
    one
      <$> into
        [32]
        ( \outs -> case outs of
            [out] -> c_evaluate kp bp out
            _ -> pure (-1)
        )

-- | liboprf's Unblind: an evaluated element without its blind.
unblind :: ByteString -> ByteString -> IO (Maybe ByteString)
unblind blind evaluated =
  bytes blind $ \rp _ -> bytes evaluated $ \ep _ ->
    one
      <$> into
        [32]
        ( \outs -> case outs of
            [out] -> c_unblind rp ep out
            _ -> pure (-1)
        )

-- | liboprf's Finalize: the OPRF's output from the input and the
-- unblinded element.
finalize :: ByteString -> ByteString -> IO (Maybe ByteString)
finalize input unblinded =
  bytes input $ \ip il -> bytes unblinded $ \up _ ->
    one
      <$> into
        [64]
        ( \outs -> case outs of
            [out] -> c_finalize ip (len16 il) up out
            _ -> pure (-1)
        )

-- | liboprf's @expand_message_xmd@ with SHA-512: a message, a domain
-- separation tag of at most 255 bytes, and the number of bytes wanted, at
-- most 255.
expandMessageXmd :: ByteString -> ByteString -> Int -> IO (Maybe ByteString)
expandMessageXmd message dst n =
  bytes message $ \mp ml -> bytes dst $ \dp dl ->
    one
      <$> into
        [n]
        ( \outs -> case outs of
            [out] -> c_expand_message_xmd mp (len16 ml) dp (fromIntegral dl) (fromIntegral n) out
            _ -> pure (-1)
        )
