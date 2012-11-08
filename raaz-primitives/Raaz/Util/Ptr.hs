{-|

This module contains function to allocate and de-allocate
memory. Essentially it exports the functions from
"Foreign.Marshal.Alloc" except that the sizes are now expressed in
type safe length units.

-}

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Util.Alloc
       ( allocaBuffer
       ) where

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
