module Modules.Defaults
       ( nBlocks
       , nSize
       , benchCipher
       ) where

import Raaz.Core.Types
import Raaz.Core.Primitives
import Raaz.Benchmark.Gadget

import Raaz.Core.Util.Ptr

-- | Number of Blocks to run benchmarks on.
nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = roundCeil nSize

nSize :: BYTES Int
nSize = 1024 * 1024 * 2

benchCipher g iv = do
  g' <- createGadget g
  return $ benchGadgetWith g' iv (nBlocks g')
