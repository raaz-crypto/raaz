{-# LANGUAGE ForeignFunctionInterface         #-}

-- | Entropy based on arc4random_buf (OpenBSD/NetBSD etc).
module Raaz.Entropy( getEntropy ) where

import Control.Monad.IO.Class(MonadIO, liftIO)
import Raaz.Core.Types


-- | The arc4random function.
foreign import ccall unsafe
  "arc4random_buf"
  c_arc4random :: Pointer      -- Message
               -> BYTES Int    -- number of bytes
               -> IO (BYTES Int)

-- | Get random bytes from using the @arc4random@ on OpenBSD/NetBSD
-- This is only used to seed the PRG and not intended for call by
-- others.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ c_arc4random ptr lenBytes >> return lenBytes
  where lenBytes = inBytes l
