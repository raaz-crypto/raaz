module Modules.Defaults (nBlocks) where

import Raaz.Types
import Raaz.Primitives

-- | Number of bytes to run benchmarks on. Currenty set to 1MB.
nBlocks :: Gadget g => g -> BLOCKS (PrimitiveOf g)
nBlocks g = cryptoCoerce (1024 * 1024 :: BYTES Int)
