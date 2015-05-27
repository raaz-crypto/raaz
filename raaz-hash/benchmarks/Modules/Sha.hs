module Modules.Sha (benchmarks) where

import Control.Applicative
import Modules.Defaults
import Raaz.Hash
import Raaz.Core.Memory

benchmarks = concat <$> sequence
             [ benchmarksAll (undefined :: SHA1) (undefined :: (MemoryCell SHA1))
             , benchmarksAll (undefined :: SHA224) (undefined :: (MemoryCell SHA256))
             , benchmarksAll (undefined :: SHA256) (undefined :: (MemoryCell SHA256))
             -- , benchmarksAll (undefined :: SHA384)
             -- , benchmarksAll (undefined :: SHA512)
             ]
