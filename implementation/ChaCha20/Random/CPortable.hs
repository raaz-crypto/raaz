{-# LANGUAGE DataKinds #-}
module ChaCha20.Random.CPortable
  ( name, description, RandomBufferSize, reseedAfter, randomBlocks
  , module ChaCha20.CPortable
  ) where

import           Raaz.Core
import qualified ChaCha20.CPortable as Base
import           ChaCha20.CPortable (Prim, Internals, BufferAlignment, additionalBlocks)
import           Raaz.Verse.Chacha20.C.Portable

name :: String
name = "chacha20-libverse-csprg"

description :: String
description = "ChaCha20 based CSPRG written in C exposed by libverse"


-------------------- CSPRG related stuff -------------------------------
-- | The number of blocks of the cipher that is generated in one go
-- encoded as a type level nat.
type RandomBufferSize = 16


-- | How many blocks of the primitive to generated before re-seeding.
reseedAfter :: BLOCKS Prim
reseedAfter = blocksOf (1024 * 1024 * 1024) (Proxy :: Proxy Prim)



randomBlocks :: AlignedPointer BufferAlignment
             -> BLOCKS Prim
             -> MT Internals ()
randomBlocks = Base.runBlockProcess verse_chacha20csprg_c_portable
