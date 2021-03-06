{-# LANGUAGE ForeignFunctionInterface         #-}

-- | Entropy based on arc4random_buf (OpenBSD/NetBSD etc).
module Entropy( getEntropy, entropySource ) where

import Raaz.Core
import Raaz.Core.Types.Internal

-- | The name of the source from which entropy is gathered. For
-- information purposes only.
entropySource :: String
entropySource = "arc4random_buf"

-- | The arc4random function.
foreign import ccall unsafe
  "arc4random_buf"
  c_arc4random :: Ptr Word8      -- Message
               -> BYTES Int    -- number of bytes
               -> IO (BYTES Int)

-- | Get random bytes from using the @arc4random@ on OpenBSD/NetBSD
-- This is only used to seed the PRG and not intended for call by
-- others.
getEntropy :: BYTES Int -> Ptr Word8 -> IO (BYTES Int)
getEntropy l ptr = c_arc4random ptr l
