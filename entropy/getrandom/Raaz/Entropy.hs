{-# LANGUAGE ForeignFunctionInterface         #-}
-- | Entropy based on the getrandom system call on Linux.
module Raaz.Entropy( getEntropy ) where

import Control.Monad.IO.Class(MonadIO, liftIO)
import Raaz.Core.Types

-- | The getrandom system call.
foreign import ccall unsafe
  "getrandom"
  c_getrandom :: Pointer      -- Message
              -> BYTES Int    -- number of bytes to be read.
              -> Int          -- flags
              -> IO (BYTES Int)

-- | Get random bytes from using the @getrandom@ system call on
-- linux. This is only used to seed the PRG and not intended for call
-- by others.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ c_getrandom ptr lenBytes 0
  where lenBytes = inBytes l
