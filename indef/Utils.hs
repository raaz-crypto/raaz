{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE MonoLocalBinds   #-}
{-# LANGUAGE CPP              #-}
module Utils
       ( processBuffer
       , processByteSource
       , transform
       ) where

import Data.ByteString          as B
import Data.ByteString.Internal as IB
import GHC.TypeLits

import Raaz.Core
import Raaz.Core.Types.Internal

import Implementation
import Buffer

-- | Process the data in the buffer.
{-# INLINE processBuffer #-}
processBuffer :: KnownNat n => Buffer n -> Internals -> IO ()
processBuffer buf = processBlocks (getBufferPointer buf) $ bufferSize $ pure buf

-- | Process a byte source.

processByteSource :: ByteSource src => src -> Internals -> IO ()
processByteSource src imem
  = allocBufferFor blks $
    \ ptr -> processChunks (processBlocks ptr blks imem)
             (\ sz -> processLast ptr sz imem)
             src blks
             $ forgetAlignment ptr
  where blks       = atLeast l1Cache :: BlockCount Prim

transform :: ByteString -> Internals -> IO ByteString
transform bs imem
  = allocBufferFor bufSz $
    \ buf ->
      let bufPtr = forgetAlignment buf
      in do unsafeCopyToPointer bs bufPtr -- Copy the input to buffer.
            processLast buf strSz imem
            IB.create sbytes $
              \ ptr -> Raaz.Core.memcpy (destination ptr) (source bufPtr) strSz
  where strSz           = Raaz.Core.length bs
        BYTES sbytes    = strSz
        --
        -- Buffer size is at least the size of the input.
        --
        bufSz           = atLeast strSz `mappend` additionalBlocks
