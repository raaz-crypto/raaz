{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha256.
module Sha256.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( castPtr      )
import Control.Monad.IO.Class     ( liftIO       )

import Raaz.Core
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (Sha256, Sha256Mem, process256Last)

import Raaz.Verse.Sha256.C.Portable

name :: String
name = "sha256-libverse-c"

description :: String
description = "Sha256 Implementation in C exposed by libverse"

type Prim                    = Sha256
type Internals               = Sha256Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS Sha256
additionalBlocks = blocksOf 1 Proxy

-- | The compression algorithm.
compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS Sha256
               -> MT Internals ()
compressBlocks buf blks = do hPtr <- castPtr <$> hashCellPointer
                             let blkPtr = castPtr $ forgetAlignment buf
                                 wBlks  = toEnum $ fromEnum blks
                               in liftIO $ verse_sha256_c_portable blkPtr wBlks hPtr


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Sha256
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength blks

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast = process256Last processBlocks
