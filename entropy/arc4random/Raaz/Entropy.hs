{-# LANGUAGE ForeignFunctionInterface         #-}
module Raaz.Entropy( getEntropy ) where

import Control.Monad.IO.Class(MonadIO, liftIO)
import Raaz.Core.Types


-- | The getrandom system call.
foreign import ccall unsafe
  "arc4random_buf"
  c_arc4random :: Pointer      -- Message
               -> BYTES Int    -- number of bytes
               -> IO (BYTES Int)

-- | Get random bytes from using the @getrandom@ system call on
-- linux. This is only used to seed the PRG and not intended for call
-- by others.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ c_arc4random ptr lenBytes >> return lenBytes
  where lenBytes = inBytes l
