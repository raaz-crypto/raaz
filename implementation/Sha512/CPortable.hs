{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha512.
module Sha512.CPortable
       ( name, primName, description
       , Prim, Internals, BufferAlignment
       , BufferPtr
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( castPtr      )

import Raaz.Core
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (Sha512, Sha512Mem, process512Last)

import Raaz.Verse.Sha512.C.Portable


name :: String
name = "libverse-c"

primName :: String
primName = "sha512"

description :: String
description = "Sha512 Implementation in C exposed by libverse"

type Prim                    = Sha512
type Internals               = Sha512Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Sha512
additionalBlocks = blocksOf 1 Proxy

compressBlocks :: BufferPtr
               -> BlockCount Sha512
               -> Internals
               -> IO ()
compressBlocks buf blks mem = let hPtr = castPtr $ hashCell128Pointer mem
                                  blkPtr = castPtr $ forgetAlignment buf
                                  wBlks  = toEnum $ fromEnum blks
                               in verse_sha512_c_portable blkPtr wBlks hPtr

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
