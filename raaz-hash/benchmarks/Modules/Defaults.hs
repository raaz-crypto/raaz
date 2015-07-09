{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE TypeFamilies              #-}

module Modules.Defaults
       ( nBlocks
       , nSize
       , benchmarksAll
       ) where

import Criterion.Main

import Raaz.Core.Primitives
import Raaz.Core.Memory
import Raaz.Core.Types
import Raaz.Benchmark.Gadget
import Raaz.Core.Primitives.Hash
--import Raaz.Types

-- | Number of Blocks to run benchmarks on.
nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = atMost nSize

nSize :: BYTES Int
nSize = 1024 * 1024

benchmarksAll h mc = sequence
                    [ benchmarkHash (toH h mc) h
                    , benchmarkHash (toC h mc) h
                    ]
  where
    benchmarkHash g p = benchmarker g (defaultKey p) (nBlocks g)
    toH :: p -> m -> HGadget p m
    toH _ _ = undefined
    toC :: p -> m -> CGadget p m
    toC _ _ = undefined
