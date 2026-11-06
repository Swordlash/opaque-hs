-- | Memory for secrets, which this package scrubs: long-lived 'Secret's,
-- and 'Scratch' buffers for the intermediate values of one operation.
--
-- A 'ByteString' is pinned, so the garbage collector never copies one, but
-- every concatenation, XOR or derivation over 'ByteString's makes a new
-- buffer, and the collector frees it without zeroing it. So inside the
-- package, a value derived from the password or from a private key never
-- becomes an ordinary 'ByteString'. It lives in one of two kinds of memory:
--
-- * A 'Secret' holds a value that outlives the operation that made it: the
--   server's setup, the client's and the server's login states (with the
--   password copied into them), and the session and export keys handed to
--   the caller. It is libsodium's @sodium_malloc@: memory outside GHC's
--   heap, between guard pages, locked with @mlock@ where the system allows
--   it, and zeroed by @sodium_free@, which the 'ForeignPtr''s finalizer
--   calls. A failure to lock (the limit on locked memory, 8 MiB under
--   systemd by default, reached with many login states held) is not an
--   error: the memory is then not locked. On wasm32-wasi there is no
--   @mmap@, @mprotect@ or @mlock@: @sodium_malloc@ falls back to
--   @posix_memalign@ with WASI's 64 KiB page, about 320 KiB for each
--   secret, with no guard pages; a browser holds only a few at a time.
--
-- * A 'Scratch' is one buffer for the intermediate values of one operation
--   (the OPRF's output, the randomized password, the envelope's keys, the
--   Diffie-Hellman products, the derived keys). @sodium_malloc@ would cost a
--   system call or three per value, and count against the limit on locked
--   memory, so a scratch buffer is pinned memory from 'allocaBytes', zeroed
--   with @sodium_memzero@ when the operation ends, whether it ends with a
--   result, an error or an exception.
--
-- Values leave either kind of memory only through the functions here that
-- copy them out: what is copied out is the caller's to protect.
module Crypto.OPAQUE.Secret
  ( -- * Secrets
    Secret
  , secretLength
  , newSecret
  , secretFromBytes
  , secretFromPtr
  , withSecret
  , copySecret
  , scrubSecret

    -- * Scratch memory
  , Scratch
  , withScratch
  , withScratchIn
  , scratch
  , withScrubbed

    -- * Bytes
  , memzero
  , sodiumReady
  )
where

import Control.Exception (evaluate, finally, mask, onException, throwIO)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.ForeignPtr
  ( FinalizerPtr
  , ForeignPtr
  , newForeignPtr
  , withForeignPtr
  )
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import GHC.IO.Exception (IOErrorType (ResourceExhausted), IOException (..))
import System.IO.Unsafe (unsafePerformIO)

foreign import ccall unsafe "sodium_init" c_sodium_init :: IO CInt

foreign import ccall unsafe "sodium_memzero"
  c_memzero :: Ptr () -> CSize -> IO ()

foreign import ccall unsafe "sodium_memcmp"
  c_memcmp :: Ptr () -> Ptr () -> CSize -> IO CInt

foreign import ccall unsafe "sodium_malloc"
  c_sodium_malloc :: CSize -> IO (Ptr Word8)

foreign import ccall unsafe "&sodium_free"
  p_sodium_free :: FinalizerPtr Word8

-- | 'sodiumReady' is libsodium's initialisation, run once. @sodium_init@
-- picks the fastest implementation of each primitive for the processor,
-- opens the source of random numbers, and reads the page size
-- @sodium_malloc@ needs. It may be called any number of times and from any
-- thread; this keeps it to one call per program.
sodiumReady :: ()
sodiumReady = unsafePerformIO $ do
  r <- c_sodium_init
  if r < 0 then ioError (userError "opaque: sodium_init failed") else pure ()
{-# NOINLINE sodiumReady #-}

-- | 'memzero' zeroes @n@ bytes with @sodium_memzero@, which the compiler
-- cannot remove as a dead store.
memzero :: Ptr Word8 -> Int -> IO ()
memzero p n = c_memzero (castPtr p) (fromIntegral n)

-- | 'Secret' is a secret value in memory this package zeroes when it is
-- freed (see the module's description). It has no 'Show' that prints the
-- bytes, and 'Eq' compares in constant time with @sodium_memcmp@.
data Secret = Secret Int (ForeignPtr Word8)

instance Show Secret where
  show _ = "<secret>"

instance Eq Secret where
  a == b =
    secretLength a == secretLength b
      && unsafePerformIO
        ( withSecret a $ \pa -> withSecret b $ \pb ->
            (== 0) <$> c_memcmp (castPtr pa) (castPtr pb) (fromIntegral (secretLength a))
        )

-- | The length of a secret in bytes.
secretLength :: Secret -> Int
secretLength (Secret n _) = n

-- | 'newSecret' allocates a secret of @n@ bytes and fills it with the
-- action, which must write every byte. If the action throws, the memory is
-- zeroed and freed at once. Out of memory (@sodium_malloc@ returning
-- NULL) is an 'IOException' of type 'ResourceExhausted'.
newSecret :: Int -> (Ptr Word8 -> IO ()) -> IO Secret
newSecret n fill = mask $ \restore -> do
  _ <- evaluate sodiumReady
  fp <- allocate n
  withForeignPtr fp (\p -> restore (fill p) `onException` memzero p n)
  pure (Secret n fp)

-- | Memory for a secret from @sodium_malloc@, with @sodium_free@, which
-- zeroes it, as its finalizer.
allocate :: Int -> IO (ForeignPtr Word8)
allocate n = do
  p <- c_sodium_malloc (fromIntegral n)
  if p == nullPtr
    then throwIO (IOError Nothing ResourceExhausted "opaque: sodium_malloc" "out of memory" Nothing Nothing)
    else newForeignPtr p_sodium_free p

-- | 'secretFromBytes' copies bytes into a new secret. The 'ByteString' it
-- was given stays where it was: that copy is the caller's to protect.
secretFromBytes :: ByteString -> IO Secret
secretFromBytes bs =
  newSecret (BS.length bs) $ \p ->
    unsafeUseAsCStringLen bs (\(q, n) -> copyBytes p (castPtr q) n)

-- | 'secretFromPtr' copies @n@ bytes from memory, a scratch buffer
-- usually, into a new secret.
secretFromPtr :: Ptr Word8 -> Int -> IO Secret
secretFromPtr q n = newSecret n (\p -> copyBytes p q n)

-- | 'withSecret' runs an action with the secret's memory. The pointer is
-- valid only inside the action: 'withForeignPtr' keeps the secret alive,
-- so its finalizer cannot free the memory while the action uses it.
withSecret :: Secret -> (Ptr Word8 -> IO a) -> IO a
withSecret (Secret _ fp) = withForeignPtr fp

-- | 'copySecret' copies a secret out into an ordinary 'ByteString'. Nothing
-- scrubs the copy: it is the caller's to protect. The package does this only
-- to encode a value the caller asked to have as bytes.
copySecret :: Secret -> IO ByteString
copySecret s@(Secret n _) =
  withSecret s $ \p -> BSI.create n (\q -> copyBytes q p n)

-- | 'scrubSecret' zeroes a secret now, for a value whose lifetime is known
-- to have ended. The memory is freed later, by the finalizer.
scrubSecret :: Secret -> IO ()
scrubSecret s@(Secret n _) = withSecret s (`memzero` n)

-- | 'Scratch' is one operation's buffer for its intermediate secrets,
-- handed out in pieces by 'scratch' and zeroed as a whole when the
-- operation ends.
data Scratch = Scratch (Ptr Word8) Int (IORef Int)

-- | 'withScratch' runs an operation with a scratch buffer of @n@ bytes,
-- pinned memory from 'allocaBytes', and zeroes the buffer when the
-- operation ends, however it ends. A result taken from the buffer must be
-- copied out and evaluated inside the operation: a value that would read
-- the buffer later would read zeros.
withScratch :: Int -> (Scratch -> IO a) -> IO a
withScratch n f = allocaBytes n (\p -> withScratchIn p n f)

-- | 'withScratchIn' is 'withScratch' over memory the caller gives. The
-- tests use it to see that the buffer is zero after an operation that
-- failed.
withScratchIn :: Ptr Word8 -> Int -> (Scratch -> IO a) -> IO a
withScratchIn p n f = do
  used <- newIORef 0
  f (Scratch p n used) `finally` memzero p n

-- | 'scratch' hands out the next @k@ bytes of a scratch buffer. A buffer
-- too small for its operation is a mistake in this package, and an error.
scratch :: Scratch -> Int -> IO (Ptr Word8)
scratch (Scratch p n used) k = do
  offset <- atomicModifyIORef' used (\o -> (o + k, o))
  if offset + k > n
    then ioError (userError "opaque: a scratch buffer is too small for its operation")
    else pure (p `plusPtr` offset)

-- | 'withScrubbed' runs an action with @n@ bytes of pinned memory that are
-- zeroed when the action ends: the temporaries of one primitive, such as a
-- hash's state.
withScrubbed :: Int -> (Ptr Word8 -> IO a) -> IO a
withScrubbed n f = allocaBytes n (\p -> f p `finally` memzero p n)
