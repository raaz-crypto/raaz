{-# LANGUAGE FlexibleContexts #-}
module Benchmark.CSPRG where

import Control.Monad
import GHC.TypeLits

import Raaz.Core
import ChaCha20.Utils
import ChaCha20.Implementation
import Benchmark.Types


bench :: KnownNat BufferAlignment => RaazBench
bench = (nm, toBenchmarkable $ action . fromIntegral)
  where action count = allocBufferFor sz $ \ ptr -> insecurely $ replicateM_ count $ csprgBlocks ptr sz
        nm = name ++ "-csprg"
        sz = atLeast nBytes
