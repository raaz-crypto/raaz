{-# LANGUAGE ForeignFunctionInterface         #-}
-- | Entropy based on the getrandom system call on Linux.
module GetRandom.Entropy( getEntropy, entropySource ) where

import Foreign.C             ( CLong(..) )

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
            -> Ptr Word8    -- Message
            -> BYTES Int    -- number of bytes to be read.
            -> Int          -- flags
            -> IO (BYTES Int)

sysGETRANDOM :: CLong
sysGETRANDOM = #const SYS_getrandom

-- | Get random bytes from using the @getrandom@ system call on
-- linux. This is only used to seed the PRG and not intended for call
-- by others.
getEntropy :: BYTES Int -> Ptr Word8 -> IO (BYTES Int)
getEntropy l ptr = c_syscall sysGETRANDOM ptr l 0
