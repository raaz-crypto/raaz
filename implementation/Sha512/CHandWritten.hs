{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha512.
module Sha512.CHandWritten
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
import Raaz.Primitive.Sha2.Internal (Sha512, Sha512Mem, process512Last)

name :: String
name = "sha512-c-handwritten"

description :: String
description = "Hand written Sha512 Implementation using portable C and Haskell FFI"

type Prim                    = Sha512
type Internals               = Sha512Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Sha512
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: BufferPtr
                     -> BlockCount Sha512
                     -> Ptr Sha512
                     -> IO ()


compressBlocks :: BufferPtr
               -> BlockCount Sha512
               -> Internals
               -> IO ()
compressBlocks buf blks = c_sha512_compress buf blks . hashCell128Pointer


processBlocks :: BufferPtr
              -> BlockCount Sha512
              -> Internals
              -> IO ()
processBlocks buf blks mem = compressBlocks buf blks mem >> updateLength128 blks mem

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast = process512Last processBlocks
