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
  , Envelope (..)
  , RegistrationRecord (..)
  , CredentialResponse (..)
  , KE1 (..)
  , KE2 (..)
  , KE3 (..)
  , ClientRegState (..)
  , ClientLoginState (..)
  , ServerLoginState (..)
  , ServerSetup (..)
  , SessionKey (..)
  , ExportKey (..)
  , Encoding (..)

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

import Control.Monad (when)
import Crypto.OPAQUE.Kdf (hkdfExpand, hkdfExtract, i2osp)
import Crypto.OPAQUE.OPRF qualified as OPRF
import Crypto.OPAQUE.Sodium
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Maybe (catMaybes, fromMaybe)
import Data.Word (Word64)

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
  | -- | The password is too long (65535 bytes or more, RFC 9497's bound on
    -- an OPRF's input), an identity or the context is longer than its
    -- two-byte length can say (65536 bytes or more), a blind is zero, or
    -- the password hashes to the group's identity (negligible probability).
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

-- | Split bytes into fields of the given lengths, or fail when the total is
-- not the input's length.
fields :: [Int] -> ByteString -> Either Error [ByteString]
fields sizes bs
  | sum sizes /= BS.length bs = Left DeserializeError
  | otherwise = Right (go sizes bs)
  where
    go [] _ = []
    go (n : ns) rest = let (a, b) = BS.splitAt n rest in a : go ns b

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
-- the OPRF evaluated under the client's key, and the server's public key.
data RegistrationResponse = RegistrationResponse
  { evaluatedMessage :: ByteString
  , serverPublicKey :: ByteString
  }
  deriving stock (Eq, Show)

instance Encoding RegistrationResponse where
  encode r = r.evaluatedMessage <> r.serverPublicKey
  decode bs =
    fields [elementBytes, elementBytes] bs >>= \case
      [e, pk] -> RegistrationResponse <$> element e <*> element pk
      _ -> Left DeserializeError

-- | 'Envelope' is what lets the client recover its private key at login: a
-- random nonce, and a MAC over the nonce and the parties' public keys and
-- identities, keyed by a key only the right password leads to.
data Envelope = Envelope
  { nonce :: ByteString
  , authTag :: ByteString
  }
  deriving stock (Eq, Show)

-- | 'RegistrationRecord' is what the server keeps for a client: the
-- client's public key, the key that masks the login's answer, and the
-- envelope. Nothing in it lets the server, or a thief of the server's
-- data, test a guess of the password without the server's OPRF seed.
data RegistrationRecord = RegistrationRecord
  { clientPublicKey :: ByteString
  , maskingKey :: ByteString
  , envelope :: Envelope
  }
  deriving stock (Eq, Show)

instance Encoding RegistrationRecord where
  encode r = r.clientPublicKey <> r.maskingKey <> r.envelope.nonce <> r.envelope.authTag
  decode bs =
    fields [elementBytes, hashBytes, nonceBytes, hashBytes] bs >>= \case
      [pk, mk, n, tag] -> do
        pk' <- element pk
        pure RegistrationRecord {clientPublicKey = pk', maskingKey = mk, envelope = Envelope n tag}
      _ -> Left DeserializeError

-- | 'CredentialResponse' is the OPRF half of KE2: the evaluated element, and
-- the server's public key and the client's envelope, encrypted under a pad
-- derived from the record's masking key.
data CredentialResponse = CredentialResponse
  { evaluatedMessage :: ByteString
  , maskingNonce :: ByteString
  , maskedResponse :: ByteString
  }
  deriving stock (Eq, Show)

-- | The length of a masked response: a public key, a nonce and a MAC.
maskedBytes :: Int
maskedBytes = elementBytes + nonceBytes + hashBytes

encodeCredentialResponse :: CredentialResponse -> ByteString
encodeCredentialResponse c = c.evaluatedMessage <> c.maskingNonce <> c.maskedResponse

-- | 'KE1' is the client's first login message: the blinded password (the
-- credential request), a nonce, and the client's ephemeral public key.
data KE1 = KE1
  { blindedMessage :: ByteString
  , clientNonce :: ByteString
  , clientPublicKeyshare :: ByteString
  }
  deriving stock (Eq, Show)

instance Encoding KE1 where
  encode k = k.blindedMessage <> k.clientNonce <> k.clientPublicKeyshare
  decode bs =
    fields [elementBytes, nonceBytes, elementBytes] bs >>= \case
      [b, n, ks] -> KE1 <$> element b <*> pure n <*> element ks
      _ -> Left DeserializeError

-- | 'KE2' is the server's login message: the credential response, a nonce,
-- the server's ephemeral public key, and a MAC that proves the server knows
-- its private key and the client's record.
data KE2 = KE2
  { credentialResponse :: CredentialResponse
  , serverNonce :: ByteString
  , serverPublicKeyshare :: ByteString
  , serverMac :: ByteString
  }
  deriving stock (Eq, Show)

instance Encoding KE2 where
  encode k = encodeCredentialResponse k.credentialResponse <> k.serverNonce <> k.serverPublicKeyshare <> k.serverMac
  decode bs =
    fields [elementBytes, nonceBytes, maskedBytes, nonceBytes, elementBytes, hashBytes] bs >>= \case
      [e, mn, mr, n, ks, mac] -> do
        e' <- element e
        ks' <- element ks
        pure
          KE2
            { credentialResponse = CredentialResponse e' mn mr
            , serverNonce = n
            , serverPublicKeyshare = ks'
            , serverMac = mac
            }
      _ -> Left DeserializeError

-- | 'KE3' is the client's last login message: a MAC that proves the client
-- recovered its private key, and so knew the password.
newtype KE3 = KE3 {clientMac :: ByteString}
  deriving stock (Eq, Show)

instance Encoding KE3 where
  encode k = k.clientMac
  decode bs = KE3 <$> (fields [hashBytes] bs >> pure bs)

-- | 'ClientRegState' is what the client keeps between its registration
-- request and the server's response: the password, the OPRF's blind, and
-- the blinded element it sent, to refuse it back as the evaluated one.
data ClientRegState = ClientRegState
  { password :: ByteString
  , blind :: ByteString
  , blinded :: ByteString
  }

instance Encoding ClientRegState where
  encode s = s.blind <> s.blinded <> s.password
  decode bs
    | BS.length bs < scalarBytes + elementBytes = Left DeserializeError
    | otherwise = do
        let (b, rest) = BS.splitAt scalarBytes bs
            (e, p) = BS.splitAt elementBytes rest
        e' <- element e
        pure (ClientRegState p b e')

-- | 'ClientLoginState' is what the client keeps between KE1 and KE2: the
-- password, the OPRF's blind, the ephemeral private key and KE1 itself.
data ClientLoginState = ClientLoginState
  { password :: ByteString
  , blind :: ByteString
  , clientSecret :: ByteString
  , ke1 :: KE1
  }

instance Encoding ClientLoginState where
  encode s = s.blind <> s.clientSecret <> encode s.ke1 <> s.password
  decode bs
    | BS.length bs < 2 * scalarBytes + ke1Bytes = Left DeserializeError
    | otherwise = do
        let (b, rest) = BS.splitAt scalarBytes bs
            (sk, rest') = BS.splitAt scalarBytes rest
            (k, p) = BS.splitAt ke1Bytes rest'
        k' <- decode k
        pure (ClientLoginState p b sk k')
    where
      ke1Bytes = 2 * elementBytes + nonceBytes

-- | 'ServerLoginState' is what the server keeps between KE2 and KE3: the
-- client's MAC it expects, and the session key it will release when that
-- MAC arrives.
data ServerLoginState = ServerLoginState
  { expectedClientMac :: ByteString
  , sessionKey :: ByteString
  }

instance Encoding ServerLoginState where
  encode s = s.expectedClientMac <> s.sessionKey
  decode bs =
    fields [hashBytes, hashBytes] bs >>= \case
      [m, k] -> Right (ServerLoginState m k)
      _ -> Left DeserializeError

-- | 'ServerSetup' is the server's long-term secret, generated once: the
-- seed every client's OPRF key is derived from, the server's key pair for
-- the key exchange, and a fake record that answers for clients with no
-- record (RFC 9807, section 6.3.2.2), so that an answer does not tell
-- whether a client exists. Losing it makes every record useless; leaking it
-- lets the thief of the records test password guesses offline.
data ServerSetup = ServerSetup
  { oprfSeed :: ByteString
  , serverPrivateKey :: ByteString
  , serverPublicKey :: ByteString
  , fakeRecord :: RegistrationRecord
  }

instance Encoding ServerSetup where
  encode s = s.oprfSeed <> s.serverPrivateKey <> s.serverPublicKey <> encode s.fakeRecord
  decode bs =
    fields [hashBytes, scalarBytes, elementBytes, elementBytes + hashBytes + nonceBytes + hashBytes] bs >>= \case
      [seed, sk, pk, fake] -> do
        pk' <- element pk
        if scalarMultBase sk /= Just pk' then Left DeserializeError else pure ()
        ServerSetup seed sk pk' <$> decode fake
      _ -> Left DeserializeError

-- | 'SessionKey' is the secret the two parties agree on at login, 64
-- bytes. Each login has a different one.
newtype SessionKey = SessionKey ByteString

instance Encoding SessionKey where
  encode (SessionKey k) = k
  decode bs = SessionKey <$> (fields [hashBytes] bs >> pure bs)

-- | 'ExportKey' is a secret, 64 bytes, that only the client can compute,
-- the same at registration and at every login with the same record. An
-- application can derive keys from it to encrypt the client's data; the
-- server never learns it. The RFC requires that it is used only after the
-- server is authenticated, which 'clientFinish' ensures by returning it
-- only then.
newtype ExportKey = ExportKey ByteString

instance Encoding ExportKey where
  encode (ExportKey k) = k
  decode bs = ExportKey <$> (fields [hashBytes] bs >> pure bs)

-- | 'generateServerSetup' makes a new 'ServerSetup' from libsodium's
-- random numbers. A server runs it once and keeps the result secret.
generateServerSetup :: IO (Either Error ServerSetup)
generateServerSetup = do
  seed <- randomBytes hashBytes
  keySeed <- randomBytes seedBytes
  fakeKey <- randomScalar
  fakeMask <- randomBytes hashBytes
  pure $ do
    fake <- maybe (Left DeriveKeyPairError) Right (fakeRecordWith fakeKey fakeMask)
    serverSetupWith seed keySeed fake

-- | 'serverSetupWith' builds a 'ServerSetup' from an OPRF seed (64 bytes), a
-- seed for the server's key pair (32 bytes) and a fake record.
serverSetupWith :: ByteString -> ByteString -> RegistrationRecord -> Either Error ServerSetup
serverSetupWith seed keySeed fake = do
  (sk, pk) <- deriveDiffieHellmanKeyPair keySeed
  pure ServerSetup {oprfSeed = seed, serverPrivateKey = sk, serverPublicKey = pk, fakeRecord = fake}

-- | 'fakeRecordWith' builds the fake record the RFC prescribes from a
-- private scalar (its public key becomes the record's) and a 64-byte masking
-- key; the envelope is all zeros.
fakeRecordWith :: ByteString -> ByteString -> Maybe RegistrationRecord
fakeRecordWith sk mask = do
  pk <- scalarMultBase sk
  pure
    RegistrationRecord
      { clientPublicKey = pk
      , maskingKey = mask
      , envelope = Envelope (BS.replicate nonceBytes 0) (BS.replicate hashBytes 0)
      }

-- | 'deriveDiffieHellmanKeyPair' is the RFC's DeriveDiffieHellmanKeyPair for
-- ristretto255: RFC 9497's DeriveKeyPair with OPAQUE's own info string.
deriveDiffieHellmanKeyPair :: ByteString -> Either Error (ByteString, ByteString)
deriveDiffieHellmanKeyPair seed =
  maybe (Left DeriveKeyPairError) Right (OPRF.deriveKeyPair seed "OPAQUE-DeriveDiffieHellmanKeyPair")

-- | Diffie-Hellman over ristretto255: a scalar times an element. Elements
-- reaching it were checked when their message was decoded.
diffieHellman :: ByteString -> ByteString -> Either Error ByteString
diffieHellman k b = maybe (Left DeserializeError) Right (scalarMult k b)

-- | 'oprfKey' is the client's OPRF key, derived from the server's OPRF seed
-- and the credential identifier (CreateRegistrationResponse's first step).
-- Every client has its own, and the server stores none of them.
oprfKey :: ServerSetup -> CredentialId -> Either Error ByteString
oprfKey setup (CredentialId cid) =
  case OPRF.deriveKeyPair (hkdfExpand setup.oprfSeed (cid <> "OprfKey") scalarBytes) "OPAQUE-DeriveKeyPair" of
    Just (k, _) -> Right k
    Nothing -> Left DeriveKeyPairError

-- | 'stretch' is the KSF's Stretch.
stretch :: Ksf -> ByteString -> Either Error ByteString
stretch Identity msg = Right msg
stretch (Argon2id ops mem) msg = maybe (Left KsfError) Right (argon2id ops mem (BS.replicate 16 0) msg)

-- | 'randomizedPassword' turns the OPRF's output into the key the envelope
-- is derived from: Extract over the output and its stretched form.
randomizedPassword :: Ksf -> ByteString -> Either Error ByteString
randomizedPassword k oprfOutput = do
  stretched <- stretch k oprfOutput
  pure (hkdfExtract "" (oprfOutput <> stretched))

-- | Blind the password, checking its length (RFC 9497, section 5.1: an
-- input is smaller than 65535 bytes). A zero blind is refused: its
-- blinded element would be the identity.
blindPassword :: ByteString -> ByteString -> Either Error (ByteString, ByteString)
blindPassword r password
  | BS.length password >= 65535 = Left InvalidInputError
  | otherwise = maybe (Left InvalidInputError) Right (OPRF.blindWith r password)

-- | Check that the context and the identities fit their two-byte lengths
-- (RFC 9807's @\<1..2^16-1>@), so that no length wraps silently.
checkLengths :: Config -> Identities -> Either Error ()
checkLengths config ids
  | any ((> 65535) . BS.length) (config.context : catMaybes [ids.client, ids.server]) = Left InvalidInputError
  | otherwise = Right ()

-- | 'registrationRequest' is CreateRegistrationRequest: the client blinds
-- its password with a random scalar, keeps the blind and sends the blinded
-- element.
registrationRequest :: ByteString -> IO (Either Error (ClientRegState, RegistrationRequest))
registrationRequest password = (`registrationRequestWith` password) <$> randomScalar

-- | 'registrationRequestWith' is 'registrationRequest' with the blind given.
registrationRequestWith :: ByteString -> ByteString -> Either Error (ClientRegState, RegistrationRequest)
registrationRequestWith r password = do
  (b, blinded) <- blindPassword r password
  pure (ClientRegState {password, blind = b, blinded}, RegistrationRequest blinded)

-- | 'registrationResponse' is CreateRegistrationResponse: the server derives
-- the client's OPRF key from its seed and the credential identifier,
-- evaluates the blinded password with it, and sends the result with its
-- public key. It keeps nothing.
registrationResponse :: ServerSetup -> CredentialId -> RegistrationRequest -> Either Error RegistrationResponse
registrationResponse setup cid request = do
  k <- oprfKey setup cid
  evaluated <- maybe (Left DeserializeError) Right (OPRF.blindEvaluate k request.blindedMessage)
  pure RegistrationResponse {evaluatedMessage = evaluated, serverPublicKey = setup.serverPublicKey}

-- | 'finalizeRegistration' is FinalizeRegistrationRequest: the client
-- unblinds the OPRF's output, stretches it into the randomized password,
-- and seals its key material in a new envelope. It sends the record to the
-- server and keeps the export key.
finalizeRegistration :: Config -> ClientRegState -> RegistrationResponse -> Identities -> IO (Either Error (RegistrationRecord, ExportKey))
finalizeRegistration config st response ids = do
  n <- randomBytes nonceBytes
  pure (finalizeRegistrationWith config n st response ids)

-- | 'finalizeRegistrationWith' is 'finalizeRegistration' with the envelope's
-- nonce given.
finalizeRegistrationWith :: Config -> ByteString -> ClientRegState -> RegistrationResponse -> Identities -> Either Error (RegistrationRecord, ExportKey)
finalizeRegistrationWith config envelopeNonce st response ids = do
  checkLengths config ids
  when (response.evaluatedMessage == st.blinded) (Left ReflectedValueError)
  _ <- element response.serverPublicKey
  oprfOutput <- maybe (Left DeserializeError) Right (OPRF.finalize st.password st.blind response.evaluatedMessage)
  rwd <- randomizedPassword config.ksf oprfOutput
  let maskingKey = hkdfExpand rwd "MaskingKey" hashBytes
  (env, clientPublicKey, exportKey) <- store rwd envelopeNonce response.serverPublicKey ids
  pure (RegistrationRecord {clientPublicKey, maskingKey, envelope = env}, ExportKey exportKey)

-- | The keys the envelope's nonce and the randomized password lead to:
-- the MAC key, the export key and the seed of the client's key pair.
envelopeKeys :: ByteString -> ByteString -> (ByteString, ByteString, ByteString)
envelopeKeys rwd n =
  ( hkdfExpand rwd (n <> "AuthKey") hashBytes
  , hkdfExpand rwd (n <> "ExportKey") hashBytes
  , hkdfExpand rwd (n <> "PrivateKey") seedBytes
  )

-- | CreateCleartextCredentials, encoded as the envelope's MAC covers it:
-- the server's public key, then each identity with its length. An identity
-- left out is the party's public key.
cleartextCredentials :: ByteString -> ByteString -> Identities -> (ByteString, ByteString, ByteString)
cleartextCredentials serverPk clientPk ids =
  (serverPk, fromMaybe serverPk ids.server, fromMaybe clientPk ids.client)

encodeCleartext :: (ByteString, ByteString, ByteString) -> ByteString
encodeCleartext (spk, sid, cid) = spk <> i2osp 2 (BS.length sid) <> sid <> i2osp 2 (BS.length cid) <> cid

-- | Store: derive the client's key pair from the randomized password and
-- the nonce, and MAC the nonce with the cleartext credentials.
store :: ByteString -> ByteString -> ByteString -> Identities -> Either Error (Envelope, ByteString, ByteString)
store rwd n serverPk ids = do
  let (authKey, exportKey, seed) = envelopeKeys rwd n
  (_, clientPk) <- deriveDiffieHellmanKeyPair seed
  let tag = hmacSha512 authKey [n, encodeCleartext (cleartextCredentials serverPk clientPk ids)]
  pure (Envelope n tag, clientPk, exportKey)

-- | Recover: derive the client's key pair again and check the envelope's
-- MAC. A wrong password, or a fake record, fails here.
recover :: ByteString -> ByteString -> Envelope -> Identities -> Either Error (ByteString, (ByteString, ByteString, ByteString), ByteString)
recover rwd serverPk env ids = do
  let (authKey, exportKey, seed) = envelopeKeys rwd env.nonce
  (clientSk, clientPk) <- deriveDiffieHellmanKeyPair seed
  let creds = cleartextCredentials serverPk clientPk ids
      expected = hmacSha512 authKey [env.nonce, encodeCleartext creds]
  if constantTimeEqual env.authTag expected
    then Right (clientSk, creds, exportKey)
    else Left EnvelopeRecoveryError

-- | 'clientStart' is GenerateKE1: the client blinds its password, makes an
-- ephemeral key pair and a nonce, and sends KE1.
clientStart :: ByteString -> IO (Either Error (ClientLoginState, KE1))
clientStart password = do
  r <- randomScalar
  n <- randomBytes nonceBytes
  seed <- randomBytes seedBytes
  pure (clientStartWith r n seed password)

-- | 'clientStartWith' is 'clientStart' with the blind, the nonce and the
-- ephemeral key's seed given.
clientStartWith :: ByteString -> ByteString -> ByteString -> ByteString -> Either Error (ClientLoginState, KE1)
clientStartWith r n keyshareSeed password = do
  (b, blinded) <- blindPassword r password
  (secret, share) <- deriveDiffieHellmanKeyPair keyshareSeed
  let ke1 = KE1 {blindedMessage = blinded, clientNonce = n, clientPublicKeyshare = share}
  pure (ClientLoginState {password, blind = b, clientSecret = secret, ke1}, ke1)

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
  seed <- randomBytes seedBytes
  let rnd = ServerRandom {maskingNonce = mn, serverNonce = sn, keyshareSeed = seed}
  pure (serverRespondWith config setup (fromMaybe setup.fakeRecord record) cid rnd ke1 ids)

-- | 'serverRespondWith' is 'serverRespond' with the record and the random
-- values given.
serverRespondWith :: Config -> ServerSetup -> RegistrationRecord -> CredentialId -> ServerRandom -> KE1 -> Identities -> Either Error (ServerLoginState, KE2)
serverRespondWith config setup record cid rnd ke1 ids = do
  checkLengths config ids
  -- CreateCredentialResponse
  k <- oprfKey setup cid
  evaluated <- maybe (Left DeserializeError) Right (OPRF.blindEvaluate k ke1.blindedMessage)
  let pad = hkdfExpand record.maskingKey (rnd.maskingNonce <> "CredentialResponsePad") maskedBytes
      plain = setup.serverPublicKey <> record.envelope.nonce <> record.envelope.authTag
      credentialResponse =
        CredentialResponse
          { evaluatedMessage = evaluated
          , maskingNonce = rnd.maskingNonce
          , maskedResponse = BS.pack (BS.zipWith xor pad plain)
          }
      (_, sid, cidentity) = cleartextCredentials setup.serverPublicKey record.clientPublicKey ids
  -- AuthServerRespond
  (eSk, ePk) <- deriveDiffieHellmanKeyPair rnd.keyshareSeed
  let pre = preamble config.context cidentity ke1 sid credentialResponse rnd.serverNonce ePk
  dh1 <- diffieHellman eSk ke1.clientPublicKeyshare
  dh2 <- diffieHellman setup.serverPrivateKey ke1.clientPublicKeyshare
  dh3 <- diffieHellman eSk record.clientPublicKey
  let (km2, km3, sessionKey) = deriveKeys (dh1 <> dh2 <> dh3) pre
      mac = hmacSha512 km2 [sha512 [pre]]
      expected = hmacSha512 km3 [sha512 [pre, mac]]
  pure
    ( ServerLoginState {expectedClientMac = expected, sessionKey}
    , KE2
        { credentialResponse
        , serverNonce = rnd.serverNonce
        , serverPublicKeyshare = ePk
        , serverMac = mac
        }
    )

-- | 'clientFinish' is GenerateKE3. The client unblinds the OPRF's output,
-- stretches it, removes the mask from the server's answer, opens its
-- envelope (which fails with a wrong password), checks the server's MAC,
-- and computes its own MAC for KE3. Only then does it return the session
-- key and the export key.
clientFinish :: Config -> ClientLoginState -> KE2 -> Identities -> Either Error (KE3, SessionKey, ExportKey)
clientFinish config st ke2 ids = do
  checkLengths config ids
  -- RecoverCredentials
  let cr = ke2.credentialResponse
  when (cr.evaluatedMessage == st.ke1.blindedMessage) (Left ReflectedValueError)
  oprfOutput <- maybe (Left DeserializeError) Right (OPRF.finalize st.password st.blind cr.evaluatedMessage)
  rwd <- randomizedPassword config.ksf oprfOutput
  let maskingKey = hkdfExpand rwd "MaskingKey" hashBytes
      pad = hkdfExpand maskingKey (cr.maskingNonce <> "CredentialResponsePad") maskedBytes
      plain = BS.pack (BS.zipWith xor pad cr.maskedResponse)
      (serverPk, rest) = BS.splitAt elementBytes plain
      (n, tag) = BS.splitAt nonceBytes rest
  (clientSk, (_, sid, cidentity), exportKey) <- recover rwd serverPk (Envelope n tag) ids
  -- The envelope's MAC covers the server's key, so a key that passes it was
  -- registered; it is checked all the same before it is used.
  _ <- element serverPk
  -- AuthClientFinalize
  dh1 <- diffieHellman st.clientSecret ke2.serverPublicKeyshare
  dh2 <- diffieHellman st.clientSecret serverPk
  dh3 <- diffieHellman clientSk ke2.serverPublicKeyshare
  let pre = preamble config.context cidentity st.ke1 sid cr ke2.serverNonce ke2.serverPublicKeyshare
      (km2, km3, sessionKey) = deriveKeys (dh1 <> dh2 <> dh3) pre
      expected = hmacSha512 km2 [sha512 [pre]]
  if constantTimeEqual ke2.serverMac expected
    then
      let clientMac = hmacSha512 km3 [sha512 [pre, expected]]
       in Right (KE3 clientMac, SessionKey sessionKey, ExportKey exportKey)
    else Left ServerAuthenticationError

-- | 'serverFinish' is ServerFinish: the server compares the client's MAC
-- with the one it expects, and releases the session key only when they
-- match.
serverFinish :: ServerLoginState -> KE3 -> Either Error SessionKey
serverFinish st ke3
  | constantTimeEqual ke3.clientMac st.expectedClientMac = Right (SessionKey st.sessionKey)
  | otherwise = Left ClientAuthenticationError

-- | Preamble: the transcript both parties MAC, with the context, the
-- identities and every message of the exchange.
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
-- key, from the Diffie-Hellman products and the transcript, through TLS
-- 1.3's Expand-Label under the label prefix @"OPAQUE-"@.
deriveKeys :: ByteString -> ByteString -> (ByteString, ByteString, ByteString)
deriveKeys ikm pre = (km2, km3, sessionKey)
  where
    prk = hkdfExtract "" ikm
    transcript = sha512 [pre]
    handshake = deriveSecret prk "HandshakeSecret" transcript
    sessionKey = deriveSecret prk "SessionKey" transcript
    km2 = deriveSecret handshake "ServerMAC" ""
    km3 = deriveSecret handshake "ClientMAC" ""

-- | Derive-Secret: Expand-Label with the output length of the hash.
deriveSecret :: ByteString -> ByteString -> ByteString -> ByteString
deriveSecret secret label ctx = expandLabel secret label ctx hashBytes

-- | Expand-Label: HKDF-Expand with TLS 1.3's encoded label as the info.
expandLabel :: ByteString -> ByteString -> ByteString -> Int -> ByteString
expandLabel secret label ctx len =
  hkdfExpand secret customLabel len
  where
    fullLabel = "OPAQUE-" <> label
    customLabel =
      BS.concat
        [ i2osp 2 len
        , i2osp 1 (BS.length fullLabel)
        , fullLabel
        , i2osp 1 (BS.length ctx)
        , ctx
        ]
