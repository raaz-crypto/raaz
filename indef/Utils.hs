{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE MonoLocalBinds   #-}
{-# LANGUAGE CPP              #-}

-- |
--
-- Module      : Utils
-- Description : A utility module for primitives.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

module Utils
       ( processByteSource
       , processBuffer
       , updateCxt
       , finaliseCxt
       , transform
       ) where

import Data.ByteString          as B
import Data.ByteString.Internal as IB
import GHC.TypeLits

import Raaz.Core

import Implementation
import Buffer
import Context

-- Warning: Not to be exposed Internal function for allocation.
allocaFor :: BlockCount Prim -> (BufferPtr -> IO a) -> IO a
allocaFor blks = allocaBuffer totalSize
  where totalSize = blks `mappend` additionalBlocks

-- | Process the complete byte source using the internals of the
-- primitive.
processByteSource :: ByteSource src => src -> Internals -> IO ()
processByteSource src imem
  = allocaFor blks $
    \ ptr -> processChunks (processBlocks ptr blks imem)
             (\ sz -> processLast ptr sz imem)
             src ptr blks
  where blks       = atLeast l1Cache :: BlockCount Prim

-- | Process the contents of the given buffer using the processBlocks action.
processBuffer :: KnownNat n
              => Buffer n
              -> Internals
              -> IO ()
processBuffer = withBufferPtr processBlocks

-- | Update the context with the data from the source. This will process
-- any complete blocks on the way so that
updateCxt :: (KnownNat n, ByteSource src)
          => src
          -> Cxt n
          -> IO ()
updateCxt  = unsafeUpdate processBlocks


-- | Finalise the computation by making use of what ever data is left
-- in the buffer.
finaliseCxt :: KnownNat n
            => Cxt n
            -> IO ()
finaliseCxt = unsafeFinalise processLast

-- | Transform the given bytestring. Hint: use this very rearely.
transform :: ByteString -> Internals -> IO ByteString
transform bs imem
  = allocaFor bufSz $
    \ buf -> do unsafeCopyToPointer bs buf -- Copy the input to buffer.
                processLast buf strSz imem
                IB.create sbytes $
                  \ ptr -> Raaz.Core.memcpy (destination ptr) (source buf) strSz
  where strSz           = Raaz.Core.length bs
        sbytes  :: Int
        sbytes  = fromEnum strSz
        --
        -- Buffer size is at least the size of the input.
        --
        bufSz           = atLeast strSz
