{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha256.
module Sha256.CHandWritten
       ( name, description
       , Prim, Internals, BufferAlignment
       , BufferPtr
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (Sha256, Sha256Mem, process256Last)

name :: String
name = "sha256-c-handwritten"

description :: String
description = "Hand written Sha256 Implementation using portable C and Haskell FFI"

type Prim                    = Sha256
type Internals               = Sha256Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Sha256
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
   c_sha256_compress  :: BufferPtr
                      -> BlockCount Sha256
                      -> Ptr Sha256
                      -> IO ()


compressBlocks :: BufferPtr
               -> BlockCount Sha256
               -> Internals
               -> IO ()
compressBlocks buf blks = c_sha256_compress buf blks . hashCellPointer


processBlocks :: BufferPtr
              -> BlockCount Sha256
              -> Internals
              -> IO ()
processBlocks buf blks mem = compressBlocks buf blks mem >> updateLength blks mem

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast = process256Last processBlocks
