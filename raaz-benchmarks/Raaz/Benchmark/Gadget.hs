{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Benchmark.Gadget
       ( benchGadget
       , benchGadgetWith
       , createGadget
       ) where

import Criterion.Main

import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

-- | Measures the performance of a gadget on the given buffer.
benchGadget  :: (Gadget g, HasName g)
             => g                      -- ^ Gadget
             -> Key (PrimitiveOf g)    -- ^ Gadget Key
             -> CryptoPtr              -- ^ Buffer on which to benchmark
             -> BLOCKS (PrimitiveOf g) -- ^ Size of Buffer
             -> Benchmark
benchGadget g iv cptr nblks = bench (getName g) process
  where
    process = do
      initialize g iv
      apply g nblks cptr

-- | Allocates the buffer and performs the benchmark
benchGadgetWith :: (Gadget g, HasName g)
                => g                      -- ^ Gadget
                -> Key (PrimitiveOf g)    -- ^ Gadget Key
                -> BLOCKS (PrimitiveOf g) -- ^ Size of random buffer which will be allocated
                -> Benchmark
benchGadgetWith g iv nblks = bench (getName g) process
  where
    process = do
      initialize g iv
      allocaBuffer rblks (go g nblks)
    go g blks cptr | blks > rblks =  apply g rblks cptr
                                  >> go g (blks - rblks) cptr
                   | otherwise    = apply g blks cptr
    rblks = recommendedBlocks g

-- Helper to satisfy typechecker
createGadget :: Gadget g => g -> IO g
createGadget _ = newGadget
