module Modules.Blake (benchmarks) where

import Control.Applicative
import Modules.Defaults
import Raaz.Hash

benchmarks = concat <$> sequence [benchmarksAll (undefined :: BLAKE256)]
