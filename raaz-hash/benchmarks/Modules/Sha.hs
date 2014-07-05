module Modules.Sha (benchmarks) where

import Control.Applicative
import Modules.Defaults
import Raaz.Hash

benchmarks = concat <$> sequence
                    [ benchmarksAll (undefined :: SHA1)
                    , benchmarksAll (undefined :: SHA224)
                    , benchmarksAll (undefined :: SHA256)
                    , benchmarksAll (undefined :: SHA384)
                    , benchmarksAll (undefined :: SHA512)
                    ]
