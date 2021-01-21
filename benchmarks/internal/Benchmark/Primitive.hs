{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Benchmark.Primitive where

import Control.Monad
import GHC.TypeLits

import Raaz.Core
import Implementation
import Benchmark.Types

-- | Number of blocks.
nblocks :: BlockCount Prim
nblocks = atLeast nBytes

allocAndRun  :: (BufferPtr -> IO ()) -> IO ()
allocAndRun  = allocaBuffer (nblocks <> additionalBlocks)

bench :: KnownNat BufferAlignment => RaazBench
bench = (nm, toBenchmarkable $ action . fromIntegral)
  where action count = allocAndRun $ doit count
        nm = name
        doit count ptr = withMemory $ \ mem -> replicateM_ count (processBlocks ptr nblocks mem)
