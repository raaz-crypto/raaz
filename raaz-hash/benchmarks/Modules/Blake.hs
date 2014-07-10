module Modules.Blake (benchmarks) where

import Control.Applicative
import Modules.Defaults
import Raaz.Hash

--benchmarks = benchmarksAll (undefined :: BLAKE256)

benchmarks = concat <$> sequence
                    [ benchmarksAll (undefined :: BLAKE256)
                    , benchmarksAll (undefined :: BLAKE2B)
                    , benchmarksAll (undefined :: BLAKE2S)                    
                    ]

