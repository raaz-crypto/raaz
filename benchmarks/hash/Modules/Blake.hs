module Modules.Blake (benchmarks) where

import Control.Applicative
import Data.Word
import Modules.Defaults
import Raaz.Core.Memory
import Raaz.Core.Types
import Raaz.Hash
import Raaz.Hash.Blake256.Internal

benchmarks = concat <$> sequence [benchmarksAll (undefined :: BLAKE256) (undefined :: (MemoryCell BLAKE256, MemoryCell Salt, MemoryCell (BITS Word64)))]
