{-|

This module contains low level function to manipulate pointers and
allocate/free memory. The size and offset types here are more friendly
to use with type safe lengths.

-}

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Util.Ptr
       ( allocaBuffer
       , movePtr
       ) where

import Foreign.Ptr
import Foreign.Marshal.Alloc


import Raaz.Types

-- | The expression @allocaBuffer l action@ allocates a local buffer
-- of length @l@ and passes it on to the IO action @action@. No
-- explicit freeing of the memory is required as the memory is
-- allocated locally and freed once the action finishes.
allocaBuffer :: CryptoCoerce l (BYTES Int)
             => l                    -- ^ buffer length
             -> (CryptoPtr -> IO b)  -- ^ the action to run
             -> IO b
allocaBuffer l action = allocaBytes bytes action
  where BYTES bytes = cryptoCoerce l

movePtr :: CryptoCoerce offset (BYTES Int)
        => CryptoPtr
        -> offset
        -> CryptoPtr
movePtr cptr offset = cptr `plusPtr` bytes
  where BYTES bytes = cryptoCoerce offset
