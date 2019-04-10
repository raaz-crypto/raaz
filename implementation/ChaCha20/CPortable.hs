{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2b.
module ChaCha20.CPortable where

import Foreign.Ptr                ( castPtr )
import Control.Monad.IO.Class     ( liftIO  )


import Raaz.Core
import Raaz.Entropy
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


-- | The number of blocks of the cipher that is generated in one go
-- encoded as a type level nat.
type RandomBufferSize = 16


-- | How many blocks of the primitive to generated before re-seeding.
reseedAfter :: BLOCKS Prim
reseedAfter = blocksOf (1024 * 1024 * 1024) (Proxy :: Proxy Prim)

-- | When using the cipher as a csprg, fill the contents of its
-- internal memory with the system entropy function.
initFromEntropyPool :: MT Internals ()
initFromEntropyPool = void $ withMemoryPtr getEntropy

randomBlocks :: AlignedPointer BufferAlignment
             -> BLOCKS Prim
             -> MT Internals ()

randomBlocks buf blks =
  do keyPtr     <- castPtr <$> keyCellPtr
     ivPtr      <- castPtr <$> ivCellPtr
     counterPtr <- castPtr <$> counterCellPtr
     let blkPtr = castPtr $ forgetAlignment buf
         wBlks  = toEnum $ fromEnum blks
         in liftIO $ verse_chacha20_c_portable_keystream blkPtr wBlks keyPtr ivPtr counterPtr
