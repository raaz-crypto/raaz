{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Modules.Sha (benchmarks) where

import Criterion.Main
import Data.Default

import Raaz.Primitives
import Raaz.Benchmark.Gadget
import Raaz.Primitives.Hash

import Raaz.Hash

import Modules.Defaults      (nBlocks)

benchHash g = benchGadgetWith g def (nBlocks g)

benchmarksAll h = [ benchHash (toH h)
                  , benchHash (toC h)
                  ]
  where
    toH :: p -> HGadget p
    toH _ = undefined
    toC :: p -> CGadget p
    toC _ = undefined

benchmarks = concat [ benchmarksAll (undefined :: SHA1)
                    , benchmarksAll (undefined :: SHA224)
                    , benchmarksAll (undefined :: SHA256)
                    , benchmarksAll (undefined :: SHA384)
                    , benchmarksAll (undefined :: SHA512)
                    ]
