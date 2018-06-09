{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2b.
module Raaz.Primitive.ChaCha20.Implementation.CPortable where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Proxy

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.ChaCha20.Internal


name :: String
name = "chacha20-cportable"

description :: String
description = "ChaCha20 Implementation using portable C and Haskell FFI"

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
