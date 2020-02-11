{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE MonoLocalBinds   #-}
{-# LANGUAGE CPP              #-}
module Utils
       ( processBuffer
       , processByteSource
       , transform
       ) where

import Control.Monad.IO.Class          (liftIO)
import Data.ByteString          as B
import Data.ByteString.Internal as IB
import Foreign.Ptr                     (castPtr)
import GHC.TypeLits

import Raaz.Core
import Raaz.Core.Types.Internal

import Implementation
import Buffer

-- | Process the data in the buffer.
{-# INLINE processBuffer #-}
processBuffer :: KnownNat n => Buffer n -> MT Internals ()
processBuffer buf = processBlocks (getBufferPointer buf) $ bufferSize $ pure buf

-- | Process a byte source.

processByteSource :: ByteSource src => src -> MT Internals ()
processByteSource src
  = allocBufferFor blks $
    \ ptr -> processChunks (processBlocks ptr blks) (processLast ptr) src blks (forgetAlignment ptr)
  where blks       = atLeast l1Cache :: BLOCKS Prim

transform :: ByteString -> MT Internals ByteString
transform bs
  = allocBufferFor bufSz $
    \ buf ->
      let bufPtr = forgetAlignment buf
      in do liftIO $ unsafeCopyToPointer bs bufPtr -- Copy the input to buffer.
            processLast buf strSz
            liftIO $ IB.create sbytes $
              \ ptr -> Raaz.Core.memcpy (destination (castPtr ptr)) (source bufPtr) strSz
  where strSz           = Raaz.Core.length bs
        BYTES sbytes    = strSz
        --
        -- Buffer size is at least the size of the input.
        --
        bufSz           = atLeast strSz `mappend` additionalBlocks
