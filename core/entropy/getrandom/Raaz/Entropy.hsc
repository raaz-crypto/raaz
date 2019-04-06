{-# LANGUAGE ForeignFunctionInterface         #-}
-- | Entropy based on the getrandom system call on Linux.
module Raaz.Entropy( getEntropy, entropySource ) where

import Foreign.C             ( CLong(..)     )
import Control.Monad.IO.Class(MonadIO, liftIO)

import Raaz.Core.Prelude
import Raaz.Core.Types
import Raaz.Core.Types.Internal

# include <unistd.h>
# include <sys/syscall.h>


-- | The name of the source from which entropy is gathered. For
-- information purposes only.
entropySource :: String
entropySource = "getrandom(linux)"

-- | The getrandom system call.
foreign import ccall unsafe
  "syscall"
  c_syscall :: CLong
            -> Pointer      -- Message
            -> BYTES Int    -- number of bytes to be read.
            -> Int          -- flags
            -> IO (BYTES Int)

sys_GETRANDOM :: CLong
sys_GETRANDOM = #const SYS_getrandom

-- | Get random bytes from using the @getrandom@ system call on
-- linux. This is only used to seed the PRG and not intended for call
-- by others.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ c_syscall sys_GETRANDOM ptr lenBytes 0
  where lenBytes = inBytes l
