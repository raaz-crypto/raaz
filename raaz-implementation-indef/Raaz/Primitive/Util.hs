{-# LANGUAGE FlexibleContexts #-}
module Raaz.Primitive.Util
       ( allocBufferFor
       , processByteSource
       , computeDigest
       , transformAndDigest
       , BufferPtr
       , module Raaz.Primitive.Implementation
       ) where

import Control.Monad.IO.Class          (liftIO)
import Data.ByteString          as B
import Data.ByteString.Internal as IB
import Foreign.Ptr                     (castPtr)
import System.IO.Unsafe                (unsafePerformIO)
import GHC.TypeLits   (KnownNat)

import Raaz.Core
import Raaz.Primitive.Implementation



-- | The pointer type associated with the buffer used by the
-- implementation.
type BufferPtr = AlignedPointer BufferAlignment

-- | Allocate a buffer for a primitive.
allocBufferFor :: (KnownNat BufferAlignment, MonadIOCont m)
               => BLOCKS Prim
               -> (BufferPtr  -> m a) -> m a
allocBufferFor blks = allocaAligned totalSize
  where totalSize = blks `mappend` additionalBlocks

-- | Process a byte source.
processByteSource :: (KnownNat BufferAlignment, ByteSource src) => src -> MT Internals ()
processByteSource src = allocBufferFor blks $ \ ptr -> do
  processChunks (processBlocks ptr blks) (processLast ptr) src blks (forgetAlignment ptr)
  where blks       = atLeast l1Cache :: BLOCKS Prim

-- | Compute the digest of a message.
computeDigest :: (KnownNat BufferAlignment, ByteSource src)
              => Key Prim -> src -> IO (Digest Prim)
computeDigest key src = insecurely $ do initialise key
                                        processByteSource src
                                        extract

-- | Transform a given bytestring using the recommended implementation
-- of a stream cipher.
transformAndDigest :: KnownNat BufferAlignment
                   => Key Prim
                   -> ByteString
                   -> (ByteString, Digest Prim)
transformAndDigest key bs = unsafePerformIO $ insecurely go
  where strSz           = Raaz.Core.length bs
        BYTES sbytes    = inBytes strSz
        --
        -- Buffer size is at least the size of the input.
        --
        bufSz           = atLeast strSz `mappend` additionalBlocks
        go :: MT Internals (B.ByteString, Digest Prim)
        --
        -- Where the action happens.
        --
        go = allocBufferFor bufSz $ \ buf ->  do
          --
          --  Copy the input string to the buffer.
          --
          let bufPtr = forgetAlignment buf
            in do liftIO $ unsafeCopyToPointer bs bufPtr -- Copy the input to buffer.
                  initialise key
                  processLast buf strSz
                  --
                  -- Copy the data in the buffer back to the destination pointer.
                  --
                  str  <- liftIO $ IB.create sbytes
                    $ \ ptr -> Raaz.Core.memcpy (destination (castPtr ptr)) (source bufPtr) strSz

                  dgst <- extract
                  return (str,dgst)

        -- | Needed by unsafeCreate
