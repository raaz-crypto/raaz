{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha512.
module Sha512.CPortable
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
import Raaz.Primitive.Sha2.Internal (Sha512, Sha512Mem, process512Last)

import Raaz.Verse.Sha512.C.Portable


name :: String
name = "sha512-libverse-c"

description :: String
description = "Sha512 Implementation in C exposed by libverse"

type Prim                    = Sha512
type Internals               = Sha512Mem
type BufferAlignment         = 32


additionalBlocks :: BlockCount Sha512
additionalBlocks = blocksOf 1 Proxy

compressBlocks :: AlignedPointer BufferAlignment
               -> BlockCount Sha512
               -> MT Internals ()
compressBlocks buf blks = do hPtr <- castPtr <$> hashCell128Pointer
                             let blkPtr = castPtr $ forgetAlignment buf
                                 wBlks  = toEnum $ fromEnum blks
                               in liftIO $ verse_sha512_c_portable blkPtr wBlks hPtr

processBlocks :: AlignedPointer BufferAlignment
              -> BlockCount Sha512
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength128 blks



-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast = process512Last processBlocks
