{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Benchmark.CSPRG where

import Control.Monad
import GHC.TypeLits

import Raaz.Core
import Benchmark.Types
import Buffer
import Implementation


-- | Number of blocks.
nblocks :: BlockCount Prim
nblocks = atLeast nBytes

allocAndRun  :: (BufferPtr -> IO ()) -> IO ()
allocAndRun  = allocaBuffer (nblocks <> additionalBlocks)

bench :: KnownNat BufferAlignment => RaazBench
bench = (name, toBenchmarkable $ action . fromIntegral)
  where action count = allocAndRun $ doit count
        doit count ptr = withMemory $ \ mem -> replicateM_ count (randomBlocks ptr nblocks mem)
