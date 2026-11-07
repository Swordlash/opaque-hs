{-# LANGUAGE DataKinds #-}

-- | The OPAQUE protocol of RFC 9807 with the 3DH key exchange, over
-- ristretto255 and SHA-512, with every random value a parameter.
--
-- This module is the protocol itself. "Crypto.OPAQUE" is its public face:
-- the same functions with the random values taken from libsodium, and the
-- types without their constructors. The functions here whose names end in
-- @With@ take their random values from the caller, so that the RFC's test
-- vectors can be reproduced; an application never needs them.
--
-- The names follow the RFC's. Each step's haddock names the RFC function it
-- implements and says in plain words what it does.
--
-- = Memory
--
-- Every value derived from the password or from a private key lives in
-- memory this package zeroes ("Crypto.OPAQUE.Secret"): the states and keys
-- a step returns are 'Secret's, and the intermediate values of one step
-- live in that step's 'Scratch' buffer, zeroed when the step ends, on its
-- error paths too. Messages, public keys, nonces and MACs that are sent are
-- ordinary 'ByteString's. The steps are pure functions; inside, each runs
-- its allocations and writes in 'IO' with 'unsafePerformIO', and copies a
-- result out of its scratch buffer, fully evaluated, before the buffer is
-- zeroed.
module Crypto.OPAQUE.Internal
  ( -- * Configuration
    Config (..)
  , Ksf (..)
  , Identities (..)
  , defaultIdentities
  , CredentialId (..)
  , Error (..)

    -- * Messages, records and states
  , RegistrationRequest (..)
  , RegistrationResponse (..)
  , registrationResponseOf
  , Envelope (..)
  , envelopeOf
  , RegistrationRecord (..)
  , registrationRecordOf
  , CredentialResponse (..)
  , credentialResponseOf
  , KE1 (..)
  , ke1Of
  , KE2 (..)
  , ke2Of
  , KE3 (..)
  , ClientRegState (..)
  , ClientLoginState (..)
  , ServerLoginState (..)
  , ServerSetup (..)
  , SessionKey (..)
  , ExportKey (..)
  , Encoding (..)
  , Scrub (..)

    -- * Setup
  , generateServerSetup
  , serverSetupWith
  , fakeRecordWith

    -- * Registration
  , registrationRequest
  , registrationRequestWith
  , registrationResponse
  , finalizeRegistration
  , finalizeRegistrationWith

    -- * Login
  , clientStart
  , clientStartWith
  , ServerRandom (..)
  , serverRespond
  , serverRespondWith
  , clientFinish
  , serverFinish

    -- * Steps, exposed for the test vectors
  , oprfKey
  , stretch
  , deriveDiffieHellmanKeyPair
  , randomizedPassword
  )
where

import Control.Monad (forM_, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Crypto.OPAQUE.Kdf (hkdfExpandInto, hkdfExtractInto, i2osp)
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Secret
import Crypto.OPAQUE.Sodium
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe (unsafeIndex, unsafeUseAsCStringLen)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Word (Word64, Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import GHC.Records (HasField (..))
import System.IO.Unsafe (unsafePerformIO)

-- | 'Config' is what both parties must agree on beyond the suite.
--
-- @context@ is the RFC's shared context string, mixed into every key the
-- exchange derives, so that a transcript of one application is useless in
-- another (the RFC's test vectors use @"OPAQUE-POC"@). @ksf@ is the key
-- stretching function the client applies to the OPRF's output: the server
-- never runs it, but must tell the client which one a record was made with.
data Config = Config
  { context :: ByteString
  , ksf :: Ksf
  }
  deriving stock (Eq, Show)

-- | 'Ksf' is the key stretching function: a slow hash that makes each guess
-- of a password expensive for someone who has stolen the server's records.
data Ksf
  = -- | No stretching: the output is the input. The RFC's test vectors use
    -- it so that they can be reproduced quickly. Never use it for real
    -- passwords.
    Identity
  | -- | Argon2id version 1.3 (RFC 9106) with parallelism 1, a salt of 16 zero
    -- bytes (the RFC's choice: the OPRF's output is already unique to the
    -- user and the server), the given number of passes and the given memory
    -- in bytes, and a 64-byte output.
    Argon2id
      { opsLimit :: Word64
      , memLimit :: Word64
      }
  deriving stock (Eq, Show)

-- | 'Identities' are the optional identities of the client and the server.
-- An identity left out stands for the party's public key, which is the
-- RFC's default and what 'defaultIdentities' gives. Both parties must use
-- the same identities at registration and at every login.
data Identities = Identities
  { client :: Maybe ByteString
  , server :: Maybe ByteString
  }
  deriving stock (Eq, Show)

-- | No identities: both stand for the parties' public keys.
defaultIdentities :: Identities
defaultIdentities = Identities {client = Nothing, server = Nothing}

-- | 'CredentialId' is the server's name for one client's record: the RFC's
-- @credential_identifier@. The server derives the client's OPRF key from it,
-- so it must never change for a record, and two records must never share
-- one.
newtype CredentialId = CredentialId ByteString
  deriving stock (Eq, Show)

-- | 'Error' is every way a step can fail, with the RFC's names.
data Error
  = -- | A message's bytes have the wrong length or hold an invalid group
    -- element.
    DeserializeError
  | -- | The password is 65535 bytes or more (RFC 9497, section 5.1), an
    -- identity or the context is longer than its two-byte length can say
    -- (65536 bytes or more), a random value given
    -- has the wrong length, a blind is zero, or the password hashes to the
    -- group's identity (negligible probability).
    InvalidInputError
  | -- | The server's evaluated element is the client's own blinded element
    -- sent back: a server that reflects the OPRF instead of evaluating it.
    -- RFC 9807 does not require the check; opaque-ke makes it, and so does
    -- this package.
    ReflectedValueError
  | -- | A key pair could not be derived from a seed (negligible probability).
    DeriveKeyPairError
  | -- | The key stretching function failed: Argon2id's limits are out of
    -- range, or its memory could not be allocated.
    KsfError
  | -- | The client could not open its envelope: the password is wrong, or
    -- the server answered for a record that does not exist.
    EnvelopeRecoveryError
  | -- | The server's MAC in KE2 is wrong.
    ServerAuthenticationError
  | -- | The client's MAC in KE3 is wrong.
    ClientAuthenticationError
  deriving stock (Eq, Show)

-- | 'Encoding' turns a value to bytes and back. Messages and records are
-- encoded exactly as the RFC's structures (fixed-length fields one after
-- another). States, which the RFC never sends, are encoded the same way;
-- a client state ends with the password. 'decode' checks lengths and that
-- every group element is valid.
class Encoding a where
  encode :: a -> ByteString
  decode :: ByteString -> Either Error a

-- Fixed sizes of this suite: Nn and Nseed (nonces and seeds), Npk and Noe
-- (elements), Nsk and Nok (scalars), Nh, Nm and Nx (hashes and MACs).
nonceBytes, seedBytes :: Int
nonceBytes = 32
seedBytes = 32

-- Messages and records are newtypes over their encoding: the RFC's
-- fixed-length fields one after another. 'encode' gives the bytes back as
-- they are, and 'decode' checks the length and the group elements once and
-- keeps the input whole. Each field is a 'HasField' instance that slices
-- the bytes at the field's offset, so @ke1.clientNonce@ reads as a record
-- field would, without a copy. A value comes only from 'decode' or from
-- the type's constructor function below (@ke1Of@ and the like), which
-- concatenates parts of the right lengths in one allocation, so every
-- slice is in range.

-- | The bytes of a field: @len@ bytes at @offset@, sharing the message's
-- buffer. A slice keeps the whole buffer alive, which for messages of a
-- few hundred bytes costs nothing worth a copy.
slice :: Int -> Int -> ByteString -> ByteString
slice offset len = BS.take len . BS.drop offset

-- | Bytes as 'decode' accepts a message: exactly @size@ of them, with a
-- valid group element at each of the given offsets.
checked :: Int -> [Int] -> ByteString -> Either Error ByteString
checked size elementsAt bs
  | BS.length bs /= size = Left DeserializeError
  | all (\o -> isValidElement (slice o elementBytes bs)) elementsAt = Right bs
  | otherwise = Left DeserializeError

-- | Accept only a valid group element other than the identity.
element :: ByteString -> Either Error ByteString
element e = if isValidElement e then Right e else Left DeserializeError

-- | 'RegistrationRequest' is the client's first registration message: the
-- password, blinded by the OPRF.
newtype RegistrationRequest = RegistrationRequest {blindedMessage :: ByteString}
  deriving stock (Eq, Show)

instance Encoding RegistrationRequest where
  encode r = r.blindedMessage
  decode bs = RegistrationRequest <$> element bs

-- | 'RegistrationResponse' is the server's answer to a registration request:
-- the OPRF evaluated under the client's key (@evaluatedMessage@), and the
-- server's public key (@serverPublicKey@).
newtype RegistrationResponse = RegistrationResponse ByteString
  deriving stock (Eq, Show)

-- | A registration response of its evaluated element and the server's
-- public key.
registrationResponseOf :: ByteString -> ByteString -> RegistrationResponse
registrationResponseOf evaluated pk = RegistrationResponse (BS.concat [evaluated, pk])

instance HasField "evaluatedMessage" RegistrationResponse ByteString where
  getField (RegistrationResponse b) = slice 0 elementBytes b

instance HasField "serverPublicKey" RegistrationResponse ByteString where
  getField (RegistrationResponse b) = slice elementBytes elementBytes b

instance Encoding RegistrationResponse where
  encode (RegistrationResponse b) = b
  decode bs = RegistrationResponse <$> checked (2 * elementBytes) [0, elementBytes] bs

-- | 'Envelope' is what lets the client recover its private key at login: a
-- random nonce (@nonce@), and a MAC (@authTag@) over the nonce and the
-- parties' public keys and identities, keyed by a key only the right
-- password leads to.
newtype Envelope = Envelope ByteString
  deriving stock (Eq, Show)

-- | The length of an envelope: a nonce and a MAC.
envelopeBytes :: Int
envelopeBytes = nonceBytes + hashBytes

-- | An envelope of its nonce and its MAC.
envelopeOf :: ByteString -> ByteString -> Envelope
envelopeOf n tag = Envelope (BS.concat [n, tag])

instance HasField "nonce" Envelope ByteString where
  getField (Envelope b) = slice 0 nonceBytes b

instance HasField "authTag" Envelope ByteString where
  getField (Envelope b) = slice nonceBytes hashBytes b

-- | 'RegistrationRecord' is what the server keeps for a client: the
-- client's public key (@clientPublicKey@), the key that masks the login's
-- answer (@maskingKey@), and the envelope (@envelope@). Nothing in it lets
-- the server, or a thief of the server's data, test a guess of the
-- password without the server's OPRF seed.
newtype RegistrationRecord = RegistrationRecord ByteString
  deriving stock (Eq, Show)

-- | The length of a record: a public key, a masking key and an envelope.
recordBytes :: Int
recordBytes = elementBytes + hashBytes + envelopeBytes

-- | A record of the client's public key, the masking key and the envelope.
registrationRecordOf :: ByteString -> ByteString -> Envelope -> RegistrationRecord
registrationRecordOf pk mask (Envelope env) = RegistrationRecord (BS.concat [pk, mask, env])

instance HasField "clientPublicKey" RegistrationRecord ByteString where
  getField (RegistrationRecord b) = slice 0 elementBytes b

instance HasField "maskingKey" RegistrationRecord ByteString where
  getField (RegistrationRecord b) = slice elementBytes hashBytes b

instance HasField "envelope" RegistrationRecord Envelope where
  getField (RegistrationRecord b) = Envelope (slice (elementBytes + hashBytes) envelopeBytes b)

instance Encoding RegistrationRecord where
  encode (RegistrationRecord b) = b
  decode bs = RegistrationRecord <$> checked recordBytes [0] bs

-- | 'CredentialResponse' is the OPRF half of KE2: the evaluated element
-- (@evaluatedMessage@), and the server's public key and the client's
-- envelope, encrypted (@maskedResponse@) under a pad derived from the
-- record's masking key and a nonce (@maskingNonce@).
newtype CredentialResponse = CredentialResponse ByteString
  deriving stock (Eq, Show)

-- | The length of a masked response: a public key, a nonce and a MAC.
maskedBytes :: Int
maskedBytes = elementBytes + nonceBytes + hashBytes

-- | The length of a credential response: an element, a nonce and a masked
-- response.
credentialResponseBytes :: Int
credentialResponseBytes = elementBytes + nonceBytes + maskedBytes

-- | A credential response of its evaluated element, its masking nonce and
-- its masked response.
credentialResponseOf :: ByteString -> ByteString -> ByteString -> CredentialResponse
credentialResponseOf evaluated mn masked = CredentialResponse (BS.concat [evaluated, mn, masked])

-- | A credential response's bytes, as KE2 and the transcript carry them.
encodeCredentialResponse :: CredentialResponse -> ByteString
encodeCredentialResponse (CredentialResponse b) = b

instance HasField "evaluatedMessage" CredentialResponse ByteString where
  getField (CredentialResponse b) = slice 0 elementBytes b

instance HasField "maskingNonce" CredentialResponse ByteString where
  getField (CredentialResponse b) = slice elementBytes nonceBytes b

instance HasField "maskedResponse" CredentialResponse ByteString where
  getField (CredentialResponse b) = slice (elementBytes + nonceBytes) maskedBytes b

-- | 'KE1' is the client's first login message: the blinded password (the
-- credential request, @blindedMessage@), a nonce (@clientNonce@), and the
-- client's ephemeral public key (@clientPublicKeyshare@).
newtype KE1 = KE1 ByteString
  deriving stock (Eq, Show)

-- | The length of KE1: two elements and a nonce.
ke1Bytes :: Int
ke1Bytes = 2 * elementBytes + nonceBytes

-- | KE1 of its blinded element, its nonce and the ephemeral public key.
ke1Of :: ByteString -> ByteString -> ByteString -> KE1
ke1Of blinded n share = KE1 (BS.concat [blinded, n, share])

instance HasField "blindedMessage" KE1 ByteString where
  getField (KE1 b) = slice 0 elementBytes b

instance HasField "clientNonce" KE1 ByteString where
  getField (KE1 b) = slice elementBytes nonceBytes b

instance HasField "clientPublicKeyshare" KE1 ByteString where
  getField (KE1 b) = slice (elementBytes + nonceBytes) elementBytes b

instance Encoding KE1 where
  encode (KE1 b) = b
  decode bs = KE1 <$> checked ke1Bytes [0, elementBytes + nonceBytes] bs

-- | 'KE2' is the server's login message: the credential response
-- (@credentialResponse@), a nonce (@serverNonce@), the server's ephemeral
-- public key (@serverPublicKeyshare@), and a MAC (@serverMac@) that proves
-- the server knows its private key and the client's record.
newtype KE2 = KE2 ByteString
  deriving stock (Eq, Show)

-- | The length of KE2: a credential response, a nonce, an element and a MAC.
ke2Bytes :: Int
ke2Bytes = credentialResponseBytes + nonceBytes + elementBytes + hashBytes

-- | KE2 of its credential response, the server's nonce, the ephemeral
-- public key and the MAC.
ke2Of :: CredentialResponse -> ByteString -> ByteString -> ByteString -> KE2
ke2Of (CredentialResponse cr) n share mac = KE2 (BS.concat [cr, n, share, mac])

instance HasField "credentialResponse" KE2 CredentialResponse where
  getField (KE2 b) = CredentialResponse (slice 0 credentialResponseBytes b)

instance HasField "serverNonce" KE2 ByteString where
  getField (KE2 b) = slice credentialResponseBytes nonceBytes b

instance HasField "serverPublicKeyshare" KE2 ByteString where
  getField (KE2 b) = slice (credentialResponseBytes + nonceBytes) elementBytes b

instance HasField "serverMac" KE2 ByteString where
  getField (KE2 b) = slice (credentialResponseBytes + nonceBytes + elementBytes) hashBytes b

instance Encoding KE2 where
  encode (KE2 b) = b
  decode bs = KE2 <$> checked ke2Bytes [0, credentialResponseBytes + nonceBytes] bs

-- | 'KE3' is the client's last login message: a MAC that proves the client
-- recovered its private key, and so knew the password.
newtype KE3 = KE3 {clientMac :: ByteString}
  deriving stock (Eq, Show)

instance Encoding KE3 where
  encode k = k.clientMac
  decode bs = KE3 <$> checked hashBytes [] bs

-- | 'ClientRegState' is what the client keeps between its registration
-- request and the server's response: the OPRF's blind and the password, in
-- one 'Secret' (the blind's 32 bytes, then the password), and the blinded
-- element it sent, to refuse it back as the evaluated one.
data ClientRegState = ClientRegState
  { secret :: Secret
  , blinded :: ByteString
  }

-- | The encoding is the blind, the blinded element and the password. It is
-- secret: a copy the caller must protect.
instance Encoding ClientRegState where
  encode s = secretEncoding s.secret [(0, scalarBytes)] s.blinded [(scalarBytes, secretLength s.secret - scalarBytes)]
  decode bs
    | BS.length bs < scalarBytes + elementBytes = Left DeserializeError
    | otherwise = do
        let (b, rest) = BS.splitAt scalarBytes bs
            (e, p) = BS.splitAt elementBytes rest
        e' <- element e
        pure (ClientRegState (secretOf [b, p]) e')

-- | 'ClientLoginState' is what the client keeps between KE1 and KE2: the
-- OPRF's blind, the ephemeral private key and the password, in one
-- 'Secret' (32 bytes, 32 bytes, then the password), and KE1 itself.
data ClientLoginState = ClientLoginState
  { secret :: Secret
  , ke1 :: KE1
  }

-- | The encoding is the blind, the ephemeral private key, KE1 and the
-- password. It is secret: a copy the caller must protect.
instance Encoding ClientLoginState where
  encode s = secretEncoding s.secret [(0, 2 * scalarBytes)] (encode s.ke1) [(2 * scalarBytes, secretLength s.secret - 2 * scalarBytes)]
  decode bs
    | BS.length bs < 2 * scalarBytes + ke1Bytes = Left DeserializeError
    | otherwise = do
        let (keys, rest) = BS.splitAt (2 * scalarBytes) bs
            (k, p) = BS.splitAt ke1Bytes rest
        k' <- decode k
        pure (ClientLoginState (secretOf [keys, p]) k')

-- | 'ServerLoginState' is what the server keeps between KE2 and KE3: the
-- client's MAC it expects, and the session key it will release when that
-- MAC arrives, in one 'Secret' of 128 bytes.
newtype ServerLoginState = ServerLoginState {secret :: Secret}

-- | The encoding is the expected MAC and the session key. It is secret: a
-- copy the caller must protect.
instance Encoding ServerLoginState where
  encode s = secretEncoding s.secret [(0, 2 * hashBytes)] BS.empty []
  decode bs
    | BS.length bs /= 2 * hashBytes = Left DeserializeError
    | otherwise = Right (ServerLoginState (secretOf [bs]))

-- | 'ServerSetup' is the server's long-term secret, generated once: the
-- seed every client's OPRF key is derived from and the server's private
-- key for the key exchange, in one 'Secret' (64 bytes, then 32), the
-- matching public key, and a fake record that answers for clients with no
-- record (RFC 9807, section 6.3.2.2), so that an answer does not tell
-- whether a client exists. Losing it makes every record useless; leaking it
-- lets the thief of the records test password guesses offline.
data ServerSetup = ServerSetup
  { secret :: Secret
  , serverPublicKey :: ByteString
  , fakeRecord :: RegistrationRecord
  }

-- | The encoding is the OPRF seed, the private key, the public key and the
-- fake record. It is secret: the server stores it, and must protect the
-- copy. Decoding refuses a private key whose public key is not the one
-- given, a zero private key among them.
instance Encoding ServerSetup where
  encode s = secretEncoding s.secret [(0, hashBytes + scalarBytes)] (s.serverPublicKey <> encode s.fakeRecord) []
  decode bs
    | BS.length bs /= hashBytes + scalarBytes + elementBytes + recordBytes = Left DeserializeError
    | otherwise = do
        let keys = slice 0 (hashBytes + scalarBytes) bs
        pk <- element (slice (hashBytes + scalarBytes) elementBytes bs)
        fake <- decode (BS.drop (hashBytes + scalarBytes + elementBytes) bs)
        let sec = secretOf [keys]
            derived = unsafePerformIO (withSecret sec (\p -> publicBytesOr elementBytes (\o -> scalarMultBaseInto o (p `plusPtr` hashBytes))))
        if derived == Just pk
          then pure ServerSetup {secret = sec, serverPublicKey = pk, fakeRecord = fake}
          else Left DeserializeError

-- | 'SessionKey' is the secret the two parties agree on at login, 64
-- bytes. Each login has a different one.
newtype SessionKey = SessionKey Secret

-- | The encoding is the key: a copy the caller must protect.
instance Encoding SessionKey where
  encode (SessionKey k) = unsafePerformIO (copySecret k)
  decode bs = SessionKey (secretOf [bs]) <$ checked hashBytes [] bs

-- | 'ExportKey' is a secret, 64 bytes, that only the client can compute,
-- the same at registration and at every login with the same record. An
-- application can derive keys from it to encrypt the client's data; the
-- server never learns it. The RFC requires that it is used only after the
-- server is authenticated, which 'clientFinish' ensures by returning it
-- only then.
newtype ExportKey = ExportKey Secret

-- | The encoding is the key: a copy the caller must protect.
instance Encoding ExportKey where
  encode (ExportKey k) = unsafePerformIO (copySecret k)
  decode bs = ExportKey (secretOf [bs]) <$ checked hashBytes [] bs

-- | 'Scrub' zeroes a value's secrets now, for a caller that knows the
-- value's lifetime has ended: a login state once the login has finished, a
-- session key once it has been used. The value must not be used afterwards.
-- Without it, the secrets are zeroed when the garbage collector frees them.
class Scrub a where
  scrub :: a -> IO ()

instance Scrub ClientRegState where scrub s = scrubSecret s.secret

instance Scrub ClientLoginState where scrub s = scrubSecret s.secret

instance Scrub ServerLoginState where scrub s = scrubSecret s.secret

instance Scrub ServerSetup where scrub s = scrubSecret s.secret

instance Scrub SessionKey where scrub (SessionKey k) = scrubSecret k

instance Scrub ExportKey where scrub (ExportKey k) = scrubSecret k

-- | A secret made of the concatenation of bytes the caller gave (a
-- decoding): the bytes are copied, and the caller's stay the caller's.
secretOf :: [ByteString] -> Secret
secretOf parts =
  unsafePerformIO . newSecret (sum (map BS.length parts)) $ \p ->
    let go _ [] = pure ()
        go offset (b : bs) = do
          copyIn (p `plusPtr` offset) b
          go (offset + BS.length b) bs
     in go 0 parts

-- | One copy of a secret's ranges around public bytes: the ranges before,
-- the public bytes, the ranges after. The copy is made in one buffer, so
-- that no intermediate copy is left behind.
secretEncoding :: Secret -> [(Int, Int)] -> ByteString -> [(Int, Int)] -> ByteString
secretEncoding sec before public after =
  unsafePerformIO . withSecret sec $ \p ->
    publicBytes total $ \o -> do
      let copyRanges offset [] = pure offset
          copyRanges offset ((from, n) : rest) = do
            copyBytes (o `plusPtr` offset) (p `plusPtr` from) n
            copyRanges (offset + n) rest
      middle <- copyRanges 0 before
      copyIn (o `plusPtr` middle) public
      _ <- copyRanges (middle + BS.length public) after
      pure ()
  where
    total = sum (map snd before) + BS.length public + sum (map snd after)

-- | Copy bytes into memory.
copyIn :: Ptr Word8 -> ByteString -> IO ()
copyIn p bs = unsafeUseAsCStringLen bs (\(q, n) -> copyBytes p (castPtr q) n)

--------------------------------------------------------------------------------
-- Running a step

-- | A step's work: 'IO' that writes secrets into memory, and stops at the
-- first error.
type Op = ExceptT Error IO

-- | Run a step as a pure function. 'unsafePerformIO' rather than its
-- dupable cousin: a duplicated evaluation could be abandoned without
-- running the handler that zeroes its scratch buffer.
pureStep :: IO (Either Error a) -> Either Error a
pureStep = unsafePerformIO

-- | Run a step's work with a scratch buffer of @n@ bytes, zeroed when the
-- work ends, however it ends.
withScratchOp :: Int -> (Scratch -> Op a) -> IO (Either Error a)
withScratchOp n f = withScratch n (runExceptT . f)

-- | Take @n@ bytes of the step's scratch buffer.
alloc :: Scratch -> Int -> Op (Ptr Word8)
alloc s n = lift (scratch s n)

-- | Fail with the error when the action reports failure.
need :: Error -> IO Bool -> Op ()
need e act = lift act >>= \ok -> unless ok (throwE e)

-- | The action's result, or the error when there is none.
needJust :: Error -> IO (Maybe a) -> Op a
needJust e act = lift act >>= maybe (throwE e) pure

-- | Fail with the error unless the condition holds.
check :: Error -> Bool -> Op ()
check e ok = unless ok (throwE e)

-- | A public element as memory, for a group operation: 'False' when it has
-- the wrong length.
withElement :: ByteString -> (Ptr Word8 -> IO Bool) -> IO Bool
withElement e f
  | BS.length e /= elementBytes = pure False
  | otherwise = unsafeUseAsCStringLen e (\(p, _) -> f (castPtr p))

-- | XOR public bytes with as many bytes of memory (a pad): the result is
-- public, a masked or unmasked response.
xorWith :: Ptr Word8 -> ByteString -> IO ByteString
xorWith pad bs =
  publicBytes (BS.length bs) $ \o ->
    forM_ [0 .. BS.length bs - 1] $ \i -> do
      x <- peekByteOff pad i :: IO Word8
      pokeByteOff o i (x `xor` unsafeIndex bs i)

--------------------------------------------------------------------------------
-- Setup

-- | The info string of the key pairs OPAQUE derives for the key exchange.
dhInfo :: ByteString
dhInfo = "OPAQUE-DeriveDiffieHellmanKeyPair"

-- | 'generateServerSetup' makes a new 'ServerSetup' from libsodium's
-- random numbers. A server runs it once and keeps the result secret.
generateServerSetup :: IO (Either Error ServerSetup)
generateServerSetup = do
  fakeMask <- randomBytes hashBytes
  fake <- withScrubbed scalarBytes $ \fakeKey -> do
    scalarRandomInto fakeKey
    fmap (fakeRecordOf fakeMask) <$> publicBytesOr elementBytes (`scalarMultBaseInto` fakeKey)
  withScrubbed seedBytes $ \keySeed -> do
    randomInto keySeed seedBytes
    setupFrom (`randomInto` hashBytes) (Mem keySeed seedBytes) fake

-- | A setup whose OPRF seed the action writes, with the private key derived
-- from the key seed.
setupFrom :: (Ptr Word8 -> IO ()) -> Part -> Maybe RegistrationRecord -> IO (Either Error ServerSetup)
setupFrom fillSeed keySeed fake = case fake of
  Nothing -> pure (Left DeriveKeyPairError)
  Just fake' -> do
    sec <- newSecret (hashBytes + scalarBytes) $ \p -> do
      fillSeed p
      memzero (p `plusPtr` hashBytes) scalarBytes
    pk <- withSecret sec (\p -> OPRF.deriveKeyPairInto (p `plusPtr` hashBytes) [keySeed] dhInfo)
    case pk of
      Nothing -> Left DeriveKeyPairError <$ scrubSecret sec
      Just pk' -> pure (Right ServerSetup {secret = sec, serverPublicKey = pk', fakeRecord = fake'})

-- | 'serverSetupWith' builds a 'ServerSetup' from an OPRF seed (64 bytes), a
-- seed for the server's key pair (32 bytes) and a fake record.
serverSetupWith :: ByteString -> ByteString -> RegistrationRecord -> Either Error ServerSetup
serverSetupWith seed keySeed fake
  | BS.length seed /= hashBytes || BS.length keySeed /= seedBytes = Left InvalidInputError
  | otherwise = pureStep (setupFrom (`copyIn` seed) (Pub keySeed) (Just fake))

-- | 'fakeRecordWith' builds the fake record the RFC prescribes from a
-- private scalar (its public key becomes the record's) and a 64-byte masking
-- key; the envelope is all zeros.
fakeRecordWith :: ByteString -> ByteString -> Maybe RegistrationRecord
fakeRecordWith sk mask
  | BS.length mask /= hashBytes = Nothing
  | otherwise = fakeRecordOf mask <$> scalarMultBase sk

fakeRecordOf :: ByteString -> ByteString -> RegistrationRecord
fakeRecordOf mask pk =
  registrationRecordOf pk mask (Envelope (BS.replicate envelopeBytes 0))

--------------------------------------------------------------------------------
-- Steps

-- | 'oprfKeyInto' writes the client's OPRF key, derived from the server's
-- OPRF seed (64 bytes at @seed@) and the credential identifier
-- (CreateRegistrationResponse's first step). Every client has its own, and
-- the server stores none of them.
oprfKeyInto :: Scratch -> Ptr Word8 -> CredentialId -> Ptr Word8 -> Op ()
oprfKeyInto s seed (CredentialId cid) out = do
  keySeed <- alloc s seedBytes
  lift (hkdfExpandInto keySeed seedBytes (Mem seed hashBytes) (cid <> "OprfKey"))
  _ <- needJust DeriveKeyPairError (OPRF.deriveKeyPairInto out [Mem keySeed seedBytes] "OPAQUE-DeriveKeyPair")
  pure ()

-- | 'oprfKey' is the client's OPRF key as bytes, for the test vectors.
oprfKey :: ServerSetup -> CredentialId -> Either Error ByteString
oprfKey setup cid = pureStep . withSecret setup.secret $ \sp ->
  withScratchOp 64 $ \s -> do
    k <- alloc s scalarBytes
    oprfKeyInto s sp cid k
    lift (publicBytes scalarBytes (\o -> copyBytes o k scalarBytes))

-- | 'stretchInto' is the KSF's Stretch, from 64 bytes at @input@ to 64 at
-- @out@.
stretchInto :: Ksf -> Ptr Word8 -> Ptr Word8 -> Op ()
stretchInto Identity out input = lift (copyBytes out input hashBytes)
stretchInto (Argon2id ops mem) out input = need KsfError (argon2idInto out (BS.replicate 16 0) (Mem input hashBytes) ops mem)

-- | 'stretch' is 'stretchInto' over bytes, for the tests.
stretch :: Ksf -> ByteString -> Either Error ByteString
stretch k msg
  | BS.length msg /= hashBytes = Left InvalidInputError
  | otherwise = pureStep . withScratchOp (2 * hashBytes) $ \s -> do
      input <- alloc s hashBytes
      out <- alloc s hashBytes
      lift (copyIn input msg)
      stretchInto k out input
      lift (publicBytes hashBytes (\o -> copyBytes o out hashBytes))

-- | 'randomizedPasswordInto' turns the OPRF's output (64 bytes at
-- @output@) into the key the envelope is derived from, at @rwd@: Extract
-- over the output and its stretched form.
randomizedPasswordInto :: Scratch -> Ksf -> Ptr Word8 -> Ptr Word8 -> Op ()
randomizedPasswordInto s k rwd output = do
  both <- alloc s (2 * hashBytes)
  lift (copyBytes both output hashBytes)
  stretchInto k (both `plusPtr` hashBytes) output
  lift (hkdfExtractInto rwd "" both (2 * hashBytes))

-- | 'randomizedPassword' is 'randomizedPasswordInto' over bytes, for the
-- test vectors.
randomizedPassword :: Ksf -> ByteString -> Either Error ByteString
randomizedPassword k output
  | BS.length output /= hashBytes = Left InvalidInputError
  | otherwise = pureStep . withScratchOp (4 * hashBytes) $ \s -> do
      input <- alloc s hashBytes
      rwd <- alloc s hashBytes
      lift (copyIn input output)
      randomizedPasswordInto s k rwd input
      lift (publicBytes hashBytes (\o -> copyBytes o rwd hashBytes))

-- | 'deriveDiffieHellmanKeyPair' is the RFC's DeriveDiffieHellmanKeyPair
-- for ristretto255 over bytes, for the tests: RFC 9497's DeriveKeyPair with
-- OPAQUE's own info string.
deriveDiffieHellmanKeyPair :: ByteString -> Either Error (ByteString, ByteString)
deriveDiffieHellmanKeyPair seed = maybe (Left DeriveKeyPairError) Right (OPRF.deriveKeyPair seed dhInfo)

-- | Check that the password fits the OPRF (RFC 9497, section 5.1: an
-- input is smaller than 65535 bytes).
checkPassword :: ByteString -> Either Error ()
checkPassword password
  | BS.length password > OPRF.maxInputBytes = Left InvalidInputError
  | otherwise = Right ()

-- | Check that the context and the identities fit their two-byte lengths
-- (RFC 9807's @\<1..2^16-1>@), so that no length wraps silently.
checkLengths :: Config -> Identities -> Either Error ()
checkLengths config ids
  | any ((> 65535) . BS.length) (config.context : catMaybes [ids.client, ids.server]) = Left InvalidInputError
  | otherwise = Right ()

--------------------------------------------------------------------------------
-- Registration

-- | 'registrationRequest' is CreateRegistrationRequest: the client copies
-- its password into secret memory, blinds it with a random scalar, keeps
-- the blind and sends the blinded element. The caller's copy of the
-- password is the caller's to protect.
registrationRequest :: ByteString -> IO (Either Error (ClientRegState, RegistrationRequest))
registrationRequest = registrationRequestFrom scalarRandomInto

-- | 'registrationRequestWith' is 'registrationRequest' with the blind given.
registrationRequestWith :: ByteString -> ByteString -> Either Error (ClientRegState, RegistrationRequest)
registrationRequestWith r password
  | BS.length r /= scalarBytes = Left InvalidInputError
  | otherwise = pureStep (registrationRequestFrom (`copyIn` r) password)

registrationRequestFrom :: (Ptr Word8 -> IO ()) -> ByteString -> IO (Either Error (ClientRegState, RegistrationRequest))
registrationRequestFrom fillBlind password = case checkPassword password of
  Left e -> pure (Left e)
  Right () -> do
    sec <- newSecret (scalarBytes + BS.length password) $ \p -> do
      fillBlind p
      copyIn (p `plusPtr` scalarBytes) password
    blinded <- withSecret sec (\p -> OPRF.blindInto p (Mem (p `plusPtr` scalarBytes) (BS.length password)))
    case blinded of
      Nothing -> Left InvalidInputError <$ scrubSecret sec
      Just b -> pure (Right (ClientRegState {secret = sec, blinded = b}, RegistrationRequest b))

-- | 'registrationResponse' is CreateRegistrationResponse: the server derives
-- the client's OPRF key from its seed and the credential identifier,
-- evaluates the blinded password with it, and sends the result with its
-- public key. It keeps nothing.
registrationResponse :: ServerSetup -> CredentialId -> RegistrationRequest -> Either Error RegistrationResponse
registrationResponse setup cid request = pureStep . withSecret setup.secret $ \sp ->
  withScratchOp 64 $ \s -> do
    k <- alloc s scalarBytes
    oprfKeyInto s sp cid k
    evaluated <- needJust DeserializeError (OPRF.blindEvaluateWith k request.blindedMessage)
    pure (registrationResponseOf evaluated setup.serverPublicKey)

-- | 'finalizeRegistration' is FinalizeRegistrationRequest: the client
-- unblinds the OPRF's output, stretches it into the randomized password,
-- and seals its key material in a new envelope. It sends the record to the
-- server and keeps the export key.
finalizeRegistration :: Config -> ClientRegState -> RegistrationResponse -> Identities -> IO (Either Error (RegistrationRecord, ExportKey))
finalizeRegistration config st response ids = do
  n <- randomBytes nonceBytes
  finalizeRegistrationIO config n st response ids

-- | 'finalizeRegistrationWith' is 'finalizeRegistration' with the envelope's
-- nonce given.
finalizeRegistrationWith :: Config -> ByteString -> ClientRegState -> RegistrationResponse -> Identities -> Either Error (RegistrationRecord, ExportKey)
finalizeRegistrationWith config envelopeNonce st response ids = pureStep (finalizeRegistrationIO config envelopeNonce st response ids)

finalizeRegistrationIO :: Config -> ByteString -> ClientRegState -> RegistrationResponse -> Identities -> IO (Either Error (RegistrationRecord, ExportKey))
finalizeRegistrationIO config envelopeNonce st response ids = withSecret st.secret $ \sp ->
  withScratchOp 2048 $ \s -> do
    ExceptT (pure (checkLengths config ids))
    check InvalidInputError (BS.length envelopeNonce == nonceBytes)
    check ReflectedValueError (response.evaluatedMessage /= st.blinded)
    _ <- ExceptT (pure (element response.serverPublicKey))
    let password = Mem (sp `plusPtr` scalarBytes) (secretLength st.secret - scalarBytes)
    output <- alloc s hashBytes
    need DeserializeError (OPRF.finalizeInto output password sp response.evaluatedMessage)
    rwd <- alloc s hashBytes
    randomizedPasswordInto s config.ksf rwd output
    maskingKey <- lift (publicBytes hashBytes (\o -> hkdfExpandInto o hashBytes (Mem rwd hashBytes) "MaskingKey"))
    export <- alloc s hashBytes
    (env, clientPublicKey) <- store s rwd envelopeNonce response.serverPublicKey ids export
    exportKey <- lift (secretFromPtr export hashBytes)
    pure (registrationRecordOf clientPublicKey maskingKey env, ExportKey exportKey)

-- | The keys the envelope's nonce and the randomized password lead to,
-- written into memory: the MAC key, the export key and the seed of the
-- client's key pair.
envelopeKeysInto :: Ptr Word8 -> ByteString -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()
envelopeKeysInto rwd n authKey exportKey seed = do
  hkdfExpandInto authKey hashBytes (Mem rwd hashBytes) (n <> "AuthKey")
  hkdfExpandInto exportKey hashBytes (Mem rwd hashBytes) (n <> "ExportKey")
  hkdfExpandInto seed seedBytes (Mem rwd hashBytes) (n <> "PrivateKey")

-- | CreateCleartextCredentials, encoded as the envelope's MAC covers it:
-- the server's public key, then each identity with its length. An identity
-- left out is the party's public key.
cleartextCredentials :: ByteString -> ByteString -> Identities -> (ByteString, ByteString, ByteString)
cleartextCredentials serverPk clientPk ids =
  (serverPk, fromMaybe serverPk ids.server, fromMaybe clientPk ids.client)

encodeCleartext :: (ByteString, ByteString, ByteString) -> ByteString
encodeCleartext (spk, sid, cid) = BS.concat [spk, i2osp 2 (BS.length sid), sid, i2osp 2 (BS.length cid), cid]

-- | Store: derive the client's key pair from the randomized password and
-- the nonce, and MAC the nonce with the cleartext credentials. The export
-- key is written at @export@.
store :: Scratch -> Ptr Word8 -> ByteString -> ByteString -> Identities -> Ptr Word8 -> Op (Envelope, ByteString)
store s rwd n serverPk ids export = do
  authKey <- alloc s hashBytes
  seed <- alloc s seedBytes
  clientSk <- alloc s scalarBytes
  lift (envelopeKeysInto rwd n authKey export seed)
  clientPk <- needJust DeriveKeyPairError (OPRF.deriveKeyPairInto clientSk [Mem seed seedBytes] dhInfo)
  tag <- lift . publicBytes hashBytes $ \o ->
    hmacSha512Into o (Mem authKey hashBytes) [Pub n, Pub (encodeCleartext (cleartextCredentials serverPk clientPk ids))]
  pure (envelopeOf n tag, clientPk)

-- | Recover: derive the client's key pair again, writing the private key at
-- @clientSk@ and the export key at @export@, and check the envelope's MAC.
-- A wrong password, or a fake record, fails here.
recover :: Scratch -> Ptr Word8 -> ByteString -> Envelope -> Identities -> Ptr Word8 -> Ptr Word8 -> Op (ByteString, ByteString, ByteString)
recover s rwd serverPk env ids clientSk export = do
  authKey <- alloc s hashBytes
  seed <- alloc s seedBytes
  expected <- alloc s hashBytes
  lift (envelopeKeysInto rwd env.nonce authKey export seed)
  clientPk <- needJust DeriveKeyPairError (OPRF.deriveKeyPairInto clientSk [Mem seed seedBytes] dhInfo)
  let creds = cleartextCredentials serverPk clientPk ids
  lift (hmacSha512Into expected (Mem authKey hashBytes) [Pub env.nonce, Pub (encodeCleartext creds)])
  need EnvelopeRecoveryError (equalTo env.authTag expected hashBytes)
  pure creds

--------------------------------------------------------------------------------
-- Login

-- | 'clientStart' is GenerateKE1: the client copies its password into
-- secret memory, blinds it, makes an ephemeral key pair and a nonce, and
-- sends KE1. The caller's copy of the password is the caller's to protect.
clientStart :: ByteString -> IO (Either Error (ClientLoginState, KE1))
clientStart password = do
  n <- randomBytes nonceBytes
  clientStartFrom scalarRandomInto n (`randomInto` seedBytes) password

-- | 'clientStartWith' is 'clientStart' with the blind, the nonce and the
-- ephemeral key's seed given.
clientStartWith :: ByteString -> ByteString -> ByteString -> ByteString -> Either Error (ClientLoginState, KE1)
clientStartWith r n keyshareSeed password
  | BS.length r /= scalarBytes || BS.length keyshareSeed /= seedBytes || BS.length n /= nonceBytes = Left InvalidInputError
  | otherwise = pureStep (clientStartFrom (`copyIn` r) n (`copyIn` keyshareSeed) password)

clientStartFrom :: (Ptr Word8 -> IO ()) -> ByteString -> (Ptr Word8 -> IO ()) -> ByteString -> IO (Either Error (ClientLoginState, KE1))
clientStartFrom fillBlind n fillSeed password = case checkPassword password of
  Left e -> pure (Left e)
  Right () -> withScrubbed seedBytes $ \seed -> do
    fillSeed seed
    sec <- newSecret (2 * scalarBytes + BS.length password) $ \p -> do
      fillBlind p
      memzero (p `plusPtr` scalarBytes) scalarBytes
      copyIn (p `plusPtr` (2 * scalarBytes)) password
    made <- withSecret sec $ \p -> do
      share <- OPRF.deriveKeyPairInto (p `plusPtr` scalarBytes) [Mem seed seedBytes] dhInfo
      blinded <- OPRF.blindInto p (Mem (p `plusPtr` (2 * scalarBytes)) (BS.length password))
      pure (share, blinded)
    case made of
      (Just share, Just blinded) ->
        let ke1 = ke1Of blinded n share
         in pure (Right (ClientLoginState {secret = sec, ke1}, ke1))
      (Nothing, _) -> Left DeriveKeyPairError <$ scrubSecret sec
      (_, Nothing) -> Left InvalidInputError <$ scrubSecret sec

-- | 'ServerRandom' is the random values of one KE2: the masking nonce, the
-- server's nonce and the seed of its ephemeral key pair.
data ServerRandom = ServerRandom
  { maskingNonce :: ByteString
  , serverNonce :: ByteString
  , keyshareSeed :: ByteString
  }

-- | 'serverRespond' is GenerateKE2. The server evaluates the client's
-- blinded password under the client's OPRF key, encrypts its public key and
-- the client's envelope under the record's masking key, makes an ephemeral
-- key pair, and computes the session's keys from three Diffie-Hellman
-- products. It keeps the client's MAC it expects and the session key, and
-- sends KE2.
--
-- With 'Nothing' for the record (a client with no record), it answers with
-- the setup's fake record, as the RFC prescribes: the answer has the same
-- shape and takes the same work, and the client fails later, at
-- 'clientFinish', exactly as with a wrong password.
serverRespond :: Config -> ServerSetup -> Maybe RegistrationRecord -> CredentialId -> KE1 -> Identities -> IO (Either Error (ServerLoginState, KE2))
serverRespond config setup record cid ke1 ids = do
  mn <- randomBytes nonceBytes
  sn <- randomBytes nonceBytes
  withScrubbed seedBytes $ \seed -> do
    randomInto seed seedBytes
    serverRespondIO config setup (fromMaybe setup.fakeRecord record) cid mn sn (Mem seed seedBytes) ke1 ids

-- | 'serverRespondWith' is 'serverRespond' with the record and the random
-- values given.
serverRespondWith :: Config -> ServerSetup -> RegistrationRecord -> CredentialId -> ServerRandom -> KE1 -> Identities -> Either Error (ServerLoginState, KE2)
serverRespondWith config setup record cid rnd ke1 ids
  | BS.length rnd.keyshareSeed /= seedBytes = Left InvalidInputError
  | otherwise = pureStep (serverRespondIO config setup record cid rnd.maskingNonce rnd.serverNonce (Pub rnd.keyshareSeed) ke1 ids)

serverRespondIO :: Config -> ServerSetup -> RegistrationRecord -> CredentialId -> ByteString -> ByteString -> Part -> KE1 -> Identities -> IO (Either Error (ServerLoginState, KE2))
serverRespondIO config setup record cid mn sn seed ke1 ids = withSecret setup.secret $ \sp ->
  withScratchOp 2048 $ \s -> do
    ExceptT (pure (checkLengths config ids))
    check InvalidInputError (BS.length mn == nonceBytes && BS.length sn == nonceBytes && partLength seed == seedBytes)
    -- CreateCredentialResponse
    k <- alloc s scalarBytes
    oprfKeyInto s sp cid k
    evaluated <- needJust DeserializeError (OPRF.blindEvaluateWith k ke1.blindedMessage)
    pad <- alloc s maskedBytes
    lift (hkdfExpandInto pad maskedBytes (Pub record.maskingKey) (mn <> "CredentialResponsePad"))
    let RegistrationRecord recorded = record
        plain = setup.serverPublicKey <> BS.drop (elementBytes + hashBytes) recorded
    masked <- lift (xorWith pad plain)
    let credentialResponse = credentialResponseOf evaluated mn masked
        (_, sid, cidentity) = cleartextCredentials setup.serverPublicKey record.clientPublicKey ids
    -- AuthServerRespond
    eSk <- alloc s scalarBytes
    ePk <- needJust DeriveKeyPairError (OPRF.deriveKeyPairInto eSk [seed] dhInfo)
    let pre = preamble config.context cidentity ke1 sid credentialResponse sn ePk
    ikm <- alloc s (3 * elementBytes)
    need DeserializeError (withElement ke1.clientPublicKeyshare (scalarMultInto ikm eSk))
    need DeserializeError (withElement ke1.clientPublicKeyshare (scalarMultInto (ikm `plusPtr` elementBytes) (sp `plusPtr` hashBytes)))
    need DeserializeError (withElement record.clientPublicKey (scalarMultInto (ikm `plusPtr` (2 * elementBytes)) eSk))
    (km2, km3, sessionKey) <- deriveKeys s ikm pre
    mac <- lift (publicBytes hashBytes (\o -> hmacSha512Into o (Mem km2 hashBytes) [Pub (sha512 [pre])]))
    st <- lift . newSecret (2 * hashBytes) $ \p -> do
      hmacSha512Into p (Mem km3 hashBytes) [Pub (sha512 [pre, mac])]
      copyBytes (p `plusPtr` hashBytes) sessionKey hashBytes
    pure
      ( ServerLoginState st
      , ke2Of credentialResponse sn ePk mac
      )

-- | 'clientFinish' is GenerateKE3. The client unblinds the OPRF's output,
-- stretches it, removes the mask from the server's answer, opens its
-- envelope (which fails with a wrong password), checks the server's MAC,
-- and computes its own MAC for KE3. Only then does it return the session
-- key and the export key.
clientFinish :: Config -> ClientLoginState -> KE2 -> Identities -> Either Error (KE3, SessionKey, ExportKey)
clientFinish config st ke2 ids = pureStep . withSecret st.secret $ \sp ->
  withScratchOp 2048 $ \s -> do
    ExceptT (pure (checkLengths config ids))
    -- RecoverCredentials
    let cr = ke2.credentialResponse
        blind = sp
        clientSecret = sp `plusPtr` scalarBytes
        password = Mem (sp `plusPtr` (2 * scalarBytes)) (secretLength st.secret - 2 * scalarBytes)
    check ReflectedValueError (cr.evaluatedMessage /= st.ke1.blindedMessage)
    output <- alloc s hashBytes
    need DeserializeError (OPRF.finalizeInto output password blind cr.evaluatedMessage)
    rwd <- alloc s hashBytes
    randomizedPasswordInto s config.ksf rwd output
    maskingKey <- alloc s hashBytes
    lift (hkdfExpandInto maskingKey hashBytes (Mem rwd hashBytes) "MaskingKey")
    pad <- alloc s maskedBytes
    lift (hkdfExpandInto pad maskedBytes (Mem maskingKey hashBytes) (cr.maskingNonce <> "CredentialResponsePad"))
    plain <- lift (xorWith pad cr.maskedResponse)
    let (serverPk, env) = BS.splitAt elementBytes plain
    clientSk <- alloc s scalarBytes
    export <- alloc s hashBytes
    (_, sid, cidentity) <- recover s rwd serverPk (Envelope env) ids clientSk export
    -- The envelope's MAC covers the server's key, so a key that passes it was
    -- registered; it is checked all the same before it is used.
    _ <- ExceptT (pure (element serverPk))
    -- AuthClientFinalize
    ikm <- alloc s (3 * elementBytes)
    need DeserializeError (withElement ke2.serverPublicKeyshare (scalarMultInto ikm clientSecret))
    need DeserializeError (withElement serverPk (scalarMultInto (ikm `plusPtr` elementBytes) clientSecret))
    need DeserializeError (withElement ke2.serverPublicKeyshare (scalarMultInto (ikm `plusPtr` (2 * elementBytes)) clientSk))
    let pre = preamble config.context cidentity st.ke1 sid cr ke2.serverNonce ke2.serverPublicKeyshare
    (km2, km3, sessionKey) <- deriveKeys s ikm pre
    expected <- alloc s hashBytes
    lift (hmacSha512Into expected (Mem km2 hashBytes) [Pub (sha512 [pre])])
    need ServerAuthenticationError (equalTo ke2.serverMac expected hashBytes)
    -- The server's MAC is the one expected, so the transcript MACed next
    -- can take it as sent.
    clientMac <- lift (publicBytes hashBytes (\o -> hmacSha512Into o (Mem km3 hashBytes) [Pub (sha512 [pre, ke2.serverMac])]))
    key <- lift (secretFromPtr sessionKey hashBytes)
    exportKey <- lift (secretFromPtr export hashBytes)
    pure (KE3 clientMac, SessionKey key, ExportKey exportKey)

-- | 'serverFinish' is ServerFinish: the server compares the client's MAC
-- with the one it expects, and releases the session key only when they
-- match.
serverFinish :: ServerLoginState -> KE3 -> Either Error SessionKey
serverFinish st ke3 = pureStep . withSecret st.secret $ \p -> do
  ok <- equalTo ke3.clientMac p hashBytes
  if ok
    then Right . SessionKey <$> secretFromPtr (p `plusPtr` hashBytes) hashBytes
    else pure (Left ClientAuthenticationError)

-- | Preamble: the transcript both parties MAC, with the context, the
-- identities and every message of the exchange. It is public.
preamble :: ByteString -> ByteString -> KE1 -> ByteString -> CredentialResponse -> ByteString -> ByteString -> ByteString
preamble ctx clientIdentity ke1 serverIdentity cr sn serverShare =
  BS.concat
    [ "OPAQUEv1-"
    , i2osp 2 (BS.length ctx)
    , ctx
    , i2osp 2 (BS.length clientIdentity)
    , clientIdentity
    , encode ke1
    , i2osp 2 (BS.length serverIdentity)
    , serverIdentity
    , encodeCredentialResponse cr
    , sn
    , serverShare
    ]

-- | DeriveKeys: the server's MAC key, the client's MAC key and the session
-- key, written into the scratch buffer, from the Diffie-Hellman products
-- (96 bytes at @ikm@) and the transcript, through TLS 1.3's Expand-Label
-- under the label prefix @"OPAQUE-"@.
deriveKeys :: Scratch -> Ptr Word8 -> ByteString -> Op (Ptr Word8, Ptr Word8, Ptr Word8)
deriveKeys s ikm pre = do
  prk <- alloc s hashBytes
  handshake <- alloc s hashBytes
  sessionKey <- alloc s hashBytes
  km2 <- alloc s hashBytes
  km3 <- alloc s hashBytes
  lift $ do
    hkdfExtractInto prk "" ikm (3 * elementBytes)
    let transcript = sha512 [pre]
    expandLabelInto handshake prk "HandshakeSecret" transcript
    expandLabelInto sessionKey prk "SessionKey" transcript
    expandLabelInto km2 handshake "ServerMAC" ""
    expandLabelInto km3 handshake "ClientMAC" ""
  pure (km2, km3, sessionKey)

-- | Derive-Secret: Expand-Label with the output length of the hash, from
-- the secret (64 bytes at @secret@) to 64 bytes at @out@. Expand-Label is
-- HKDF-Expand with TLS 1.3's encoded label as the info.
expandLabelInto :: Ptr Word8 -> Ptr Word8 -> ByteString -> ByteString -> IO ()
expandLabelInto out secret label ctx =
  hkdfExpandInto out hashBytes (Mem secret hashBytes) customLabel
  where
    fullLabel = "OPAQUE-" <> label
    customLabel =
      BS.concat
        [ i2osp 2 hashBytes
        , i2osp 1 (BS.length fullLabel)
        , fullLabel
        , i2osp 1 (BS.length ctx)
        , ctx
        ]
