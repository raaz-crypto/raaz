{-# LANGUAGE DataKinds #-}
module ChaCha20.Random.CPortable
  ( name, primName, description, RandomBufferSize, reseedAfter, randomBlocks
  , module ChaCha20.CPortable
  ) where

import           Raaz.Core
import qualified ChaCha20.CPortable as Base
import           ChaCha20.CPortable (Prim, Internals, BufferAlignment, BufferPtr, additionalBlocks)
import           Raaz.Verse.ChaCha20.C.Portable

name :: String
name = "libverse-c"

primName :: String
primName = "chacha20-csprg"

description :: String
description = "ChaCha20 based CSPRG (machine endian version) written in C exposed by libverse."


-------------------- CSPRG related stuff -------------------------------
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
randomBlocks = Base.runBlockProcess verse_chacha20csprg_c_portable
