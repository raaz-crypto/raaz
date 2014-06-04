{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Modules.Sha (benchmarks) where

import Control.Applicative
import Criterion.Main
import Data.Default

import Raaz.Primitives
import Raaz.Benchmark.Gadget
import Raaz.Primitives.Hash

import Raaz.Hash

import Modules.Defaults      (nBlocks)

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

benchmarks = concat <$> sequence
                    [ benchmarksAll (undefined :: SHA1)
                    , benchmarksAll (undefined :: SHA224)
                    , benchmarksAll (undefined :: SHA256)
                    , benchmarksAll (undefined :: SHA384)
                    , benchmarksAll (undefined :: SHA512)
                    ]
