{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2b.
module ChaCha20.CHandWritten where

import Control.Monad.IO.Class     ( liftIO       )
import Foreign.Ptr                ( Ptr          )

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.ChaCha20.Internal


name :: String
name = "chacha20-c-handwritten"

description :: String
description = "Hand written ChaCha20 Implementation using portable C"

type Prim                    = ChaCha20
type Internals               = ChaCha20Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS ChaCha20
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

-- | Chacha20 block transformation.
foreign import ccall unsafe
  "raaz/cipher/chacha20/cportable.h raazChaCha20Block"
  c_chacha20_block :: AlignedPointer BufferAlignment -- message
                   -> BLOCKS ChaCha20                -- number of blocks
                   -> Ptr KEY                        -- key
                   -> Ptr IV                         -- iv
                   -> Ptr Counter                    -- Counter value
                   -> IO ()

processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()

processBlocks buf blks =
  do keyPtr     <- keyCellPtr
     ivPtr      <- ivCellPtr
     counterPtr <- counterCellPtr
     liftIO     $ c_chacha20_block buf blks keyPtr ivPtr counterPtr

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf = processBlocks buf . atLeast

-- | The number of blocks of the cipher that is generated in one go
-- encoded as a type level nat.
type RandomBufferSize = 16


-- | How many blocks of the primitive to generated before re-seeding.
reseedAfter :: BLOCKS Prim
reseedAfter = blocksOf (1024 * 1024 * 1024) (Proxy :: Proxy Prim)

randomBlocks :: AlignedPointer BufferAlignment
             -> BLOCKS Prim
             -> MT Internals ()

randomBlocks  = processBlocks
