{-# LANGUAGE FlexibleContexts #-}
module Benchmark.Primitive where

import Control.Monad
import GHC.TypeLits

import Raaz.Core
import Raaz.Primitive.Util
import Benchmark.Types


bench :: KnownNat BufferAlignment => RaazBench
bench = (nm, toBenchmarkable $ action . fromIntegral)
  where action count = allocBufferFor sz $ \ ptr -> insecurely $ replicateM_ count $ processBlocks ptr sz
        nm = name
        sz = atLeast nBytes
