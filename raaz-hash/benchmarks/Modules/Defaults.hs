{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Modules.Defaults
       ( nBlocks
       , nSize
       , benchmarksAll
       ) where

import Criterion.Main
import Data.Default

import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Benchmark.Gadget
import Raaz.Core.Primitives.Hash
--import Raaz.Types

-- | Number of Blocks to run benchmarks on.
nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = roundFloor nSize

nSize :: BYTES Int
nSize = 1024 * 1024

benchHash g = do
  g' <- createGadget g
  return $ benchGadgetWith g' def (nBlocks g')

benchmarksAll h = sequence
                  [ benchHash (toH h)
                  , benchHash (toC h)
                  ]
  where
    toH :: p -> HGadget p
    toH _ = undefined
    toC :: p -> CGadget p
    toC _ = undefined
