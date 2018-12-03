{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2b.
module ChaCha20.CPortable where

import Foreign.Ptr                ( castPtr )
import Control.Monad.IO.Class     ( liftIO  )
import Data.Proxy

import Raaz.Core
import Raaz.Primitive.ChaCha20.Internal
import Raaz.Verse.Chacha20.C.Portable

name :: String
name = "chacha20-libverse-c"

description :: String
description = "ChaCha20 Implementation in C exposed by libverse"

type Prim                    = ChaCha20
type Internals               = ChaCha20Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS ChaCha20
additionalBlocks = blocksOf 1 Proxy

processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()

processBlocks buf blks =
  do keyPtr     <- castPtr <$> keyCellPtr
     ivPtr      <- castPtr <$> ivCellPtr
     counterPtr <- castPtr <$> counterCellPtr
     let blkPtr = castPtr $ forgetAlignment buf
         wBlks  = toEnum $ fromEnum blks
         in liftIO $ verse_chacha20_c_portable blkPtr wBlks keyPtr ivPtr counterPtr

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf = processBlocks buf . atLeast

csprgBlocks :: AlignedPointer BufferAlignment
            -> BLOCKS Prim
            -> MT Internals ()

csprgBlocks buf blks =
  do keyPtr     <- castPtr <$> keyCellPtr
     ivPtr      <- castPtr <$> ivCellPtr
     counterPtr <- castPtr <$> counterCellPtr
     let blkPtr = castPtr $ forgetAlignment buf
         wBlks  = toEnum $ fromEnum blks
         in liftIO $ verse_chacha20_c_portable_keystream blkPtr wBlks keyPtr ivPtr counterPtr
