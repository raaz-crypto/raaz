{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Modules.Defaults
       ( nBlocks
       , nSize
       , benchmarksAll
       ) where

import Criterion.Main

import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Benchmark.Gadget
import Raaz.Core.Primitives.Hash
--import Raaz.Types

-- | Number of Blocks to run benchmarks on.
nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = atMost nSize

nSize :: BYTES Int
nSize = 1024 * 1024

benchHash g = do
  g'     <- createGadget g
  return $ benchGadgetWith g' (defaultKey $ primitiveOf g) (nBlocks g')

benchmarksAll h mc = sequence
                    [ benchHash (toH h mc)
                    , benchHash (toC h mc)
                    ]
  where
    toH :: p -> m -> HGadget p m
    toH _ _ = undefined
    toC :: p -> m -> CGadget p m
    toC _ _ = undefined
