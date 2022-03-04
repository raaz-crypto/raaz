{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha256.
module Sha256.CPortable
       ( name, primName, description
       , Prim, Internals, BufferAlignment
       , BufferPtr
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( castPtr      )

import Raaz.Core
import Raaz.Core.Types.Internal

import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (Sha256, Sha256Mem, process256Last)

import Raaz.Verse.Sha256.C.Portable

name :: String
name = "libverse-c"

primName :: String
primName = "sha256"

description :: String
description = "Sha256 Implementation in C exposed by libverse"

type Prim                    = Sha256
type Internals               = Sha256Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Sha256
additionalBlocks = blocksOf 1 Proxy

-- | The compression algorithm.
compressBlocks :: BufferPtr
               -> BlockCount Sha256
               -> Internals
               -> IO ()
compressBlocks buf blks mem = let hPtr = castPtr $ hashCellPointer mem
                                  blkPtr = castPtr $ forgetAlignment buf
                                  wBlks  = toEnum $ fromEnum blks
                              in verse_sha256_c_portable blkPtr wBlks hPtr


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
