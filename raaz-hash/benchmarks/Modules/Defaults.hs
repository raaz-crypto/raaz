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

actionH :: ( PrimitiveOf (HGadget p m) ~ p
           , Gadget (HGadget p m)
           , (HGadget p m) ~ g
           , Eq (Key p)
           , Hash p
           , HasName p
           ) => p -> m -> g -> IO Benchmark
actionH p m g = return $ benchGadgetWith g (defaultKey p) (nBlocks g)

actionC :: ( PrimitiveOf (CGadget p m) ~ p
           , Gadget (CGadget p m)
           , (CGadget p m) ~ g
           , Eq (Key p)
           , Hash p
           , HasName p
           ) => p -> m -> g -> IO Benchmark
actionC p m g = return $ benchGadgetWith g (defaultKey p) (nBlocks g)

benchmarksAll h mc = sequence
                    [ withMemory (actionH h mc)
                    , withMemory (actionC h mc)
                    ]
