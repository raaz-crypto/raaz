module Modules.Defaults
       ( nBlocks
       , nSize
       ) where

import Raaz.Types
import Raaz.Primitives

-- | Number of Blocks to run benchmarks on.
nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = cryptoCoerce nSize

nSize :: BYTES Int
nSize = 1024 * 1024
