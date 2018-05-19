{-# LANGUAGE FlexibleContexts #-}
module Raaz.Primitive.Util
       ( allocBufferFor
       , processByteSource
       , computeDigest
       ) where

import GHC.TypeLits   (KnownNat)
import Raaz.Core
import Raaz.Primitive.Implementation

-- | Allocate a buffer for a primitive.
allocBufferFor :: (KnownNat BufferAlignment, MonadAlloc m)
               => BLOCKS Prim
               -> (BufferPrim  -> m a) -> m a
allocBufferFor blks = allocaAligned totalSize
  where totalSize = blks <> additionalBlocks

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
