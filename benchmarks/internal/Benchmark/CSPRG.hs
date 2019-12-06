{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Benchmark.CSPRG where

import Control.Monad
import GHC.TypeLits

import Raaz.Core
import Benchmark.Types
import Implementation
import Buffer

bench :: KnownNat BufferAlignment => RaazBench
bench = (nm, toBenchmarkable $ action . fromIntegral)
  where action count = allocBufferFor sz $ \ ptr -> insecurely $ replicateM_ count $ randomBlocks ptr sz
        nm = name ++ "-csprg"
        sz = atLeast nBytes
