{-# LANGUAGE CPP #-}
module Raaz.Entropy( getEntropy ) where

#include <Windows.h>
#include <Wincrypt.h>

##if defined(i386_HOST_ARCH)
## define WINDOWS_CCONV stdcall
##elif defined(x86_64_HOST_ARCH)
## define WINDOWS_CCONV ccall
##else
## error Unknown mingw32 arch
##endif

import Control.Monad.IO.Class( MonadIO, liftIO)
import Data.Bits ((.|.))
import Data.Word (Word8(), Word32())
import Foreign.Ptr (Ptr(), nullPtr)
import Foreign.Marshal.Array (mallocArray, peekArray)
import Foreign.Marshal.Alloc (mallocBytes)
import Foreign.ForeignPtr (ForeignPtr(), withForeignPtr)
import Foreign.Concurrent (newForeignPtr)
import Foreign.C.String (CWString())
import Foreign.Storable (peek)
import System.IO.Unsafe (unsafePerformIO)
import Raaz.Core

type HCRYPTPROV = Ptr ()

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptGenRandom"
    c_CryptGenRandom :: HCRYPTPROV -> Word32 -> Ptr Word8 -> IO Bool

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptAcquireContext"
    c_CryptAcquireContext :: Ptr HCRYPTPROV -> CWString -> CWString
                          -> Word32 -> Word32 -> IO Bool

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptReleaseContext"
    c_CryptReleaseContext :: HCRYPTPROV -> Word32 -> IO Bool

-- | Cache the crypto context so we don't have to create it on each call.
cryptoContext :: ForeignPtr (HCRYPTPROV)
cryptoContext = unsafePerformIO $
  do buffer <- mallocForeignPtrBytes (#size HCRYPTPROV)
     ctx    <- newForeignPtr buffer (freeContext buffer)
     ctx_ok <- withForeignPtr ctx $ \ptr ->
                    c_CryptAcquireContext ptr nullPtr nullPtr
                        (#const PROV_RSA_FULL)
                        ((#const CRYPT_VERIFYCONTEXT) .|. (#const CRYPT_SILENT))
     if ctx_ok
        then return ctx
        else error "Call to CryptAcquireContext failed."

-- | Release the crytographical context handle.
freeContext :: HCRYPTPROV -> IO ()
freeContext ctx = c_CryptReleaseContext ctx 0 >> return ()

genRandomBytes :: HCRYPTPROV -> Word32 -> IO [Word8]
genRandomBytes ctx n = withForeignPtr ctx $ \ptr ->
  do ptr'    <- peek ptr
     buffer  <- mallocArray n
     success <- c_CryptGenRandom ptr' n buffer
     if success
        then peekArray n buffer
        else error "Call to CryptGenRandom failed."

-- | Get cryptographically random bytes from the system.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
--getEntropy l ptr = liftIO $ withBinaryFile "/dev/urandom" ReadMode $ \ hand -> hFillBuf hand ptr l
getEntropy l ptr = liftIO $
  do undefined
