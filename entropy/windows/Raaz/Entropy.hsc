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
import Foreign.Ptr (Ptr(), nullPtr, castPtr)
import Foreign.Marshal.Array (mallocArray, peekArray)
import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Marshal.Utils (new)
import Foreign.Storable (peek)
import Foreign.ForeignPtr (ForeignPtr(), withForeignPtr)
import Foreign.Concurrent (newForeignPtr)
import Foreign.C.String (CWString())
import System.IO.Unsafe (unsafePerformIO)
import Raaz.Core

type HCRYPTPROV = Ptr ()

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptGenRandom"
    c_CryptGenRandom :: HCRYPTPROV -> Word32 -> Ptr Word8 -> IO Bool

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptAcquireContextW"
    c_CryptAcquireContext :: Ptr HCRYPTPROV -> CWString -> CWString
                          -> Word32 -> Word32 -> IO Bool

foreign import WINDOWS_CCONV unsafe "Wincrypt.h CryptReleaseContext"
    c_CryptReleaseContext :: HCRYPTPROV -> Word32 -> IO Bool

-- | Cache the crypto context so we don't have to create it on each call.
cryptoContext :: ForeignPtr HCRYPTPROV
cryptoContext = unsafePerformIO $
  do buffer <- mallocBytes (#size HCRYPTPROV)
     addr   <- new buffer
     ctx    <- newForeignPtr addr (freeContext buffer >> free addr)
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

-- | Get cryptographically random bytes from the system.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ withForeignPtr cryptoContext $ \ctx ->
    do ctx' <- peek ctx
       success <- c_CryptGenRandom ctx' (fromIntegral bytes) (castPtr ptr)
       return $ if success then BYTES bytes else BYTES 0
  where BYTES bytes = inBytes l
