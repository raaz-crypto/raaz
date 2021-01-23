{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2b.
module ChaCha20.CHandWritten where

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
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount ChaCha20
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

-- | Chacha20 block transformation.
foreign import ccall unsafe
  "raaz/cipher/chacha20/cportable.h raazChaCha20Block"
  c_chacha20_block :: BufferPtr -- message
                   -> BlockCount ChaCha20                -- number of blocks
                   -> Ptr (Key ChaCha20)             -- key
                   -> Ptr (Nounce ChaCha20)          -- iv
                   -> Ptr (WordType ChaCha20)
                   -> IO ()

processBlocks :: BufferPtr
              -> BlockCount Prim
              -> Internals
              -> IO ()

processBlocks buf blks mem =
  let keyPtr     = keyCellPtr mem
      ivPtr      = ivCellPtr mem
      counterPtr = counterCellPtr mem
  in c_chacha20_block buf blks keyPtr ivPtr counterPtr

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast buf = processBlocks buf . atLeast

-- | The number of blocks of the cipher that is generated in one go
-- encoded as a type level nat.
type RandomBufferSize = 16


-- | How many blocks of the primitive to generated before re-seeding.
reseedAfter :: BlockCount Prim
reseedAfter = blocksOf (1024 * 1024 * 1024) (Proxy :: Proxy Prim)

randomBlocks :: BufferPtr
             -> BlockCount Prim
             -> Internals
             -> IO ()

randomBlocks  = processBlocks
