{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Benchmark.Gadget
       ( benchGadget
       , benchGadgetWith
       , createGadget
       , benchmarker
       ) where

import Criterion.Main

import Raaz.Core.Memory
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
  where process = initializeMemory g iv >> apply g nblks cptr

-- | Allocates the buffer and performs the benchmark
benchGadgetWith :: (Gadget g, HasName g)
                => g                      -- ^ Gadget
                -> Key (PrimitiveOf g)    -- ^ Gadget Key
                -> BLOCKS (PrimitiveOf g) -- ^ Size of random buffer which will be allocated
                -> Benchmark
benchGadgetWith g iv nblks = bench (getName g) process
  where
    process = do
      initializeMemory g iv
      allocaBuffer rblks (go nblks)
    go blks cptr | blks > rblks =  apply g rblks cptr
                                >> go (blks - rblks) cptr
                 | otherwise    = apply g blks cptr
    rblks = recommendedBlocks g

-- Helper to satisfy typechecker
createGadget :: Gadget g => g -> IO g
createGadget _ = return undefined

benchmarker :: ( Gadget g
               , HasName g
               ) => g                      -- ^ Gadget
                 -> Key (PrimitiveOf g)    -- ^ Gadget Key
                 -> BLOCKS (PrimitiveOf g) -- ^ Size of random buffer which will be allocated
                 -> IO Benchmark
benchmarker g iv nblks = return $ bench (getName g) benchAction
  where process :: ( g1 ~ g
                   , Gadget g1
                   , Key (PrimitiveOf g) ~ Key (PrimitiveOf g1)
                   ) => Key (PrimitiveOf g1) -> BLOCKS (PrimitiveOf g1) -> g1 -> g1 -> IO ()
        process iv1 nblks1 _ g1 = do
          let rblks = recommendedBlocks g1
              go blks g' cptr | blks > rblks = apply g' rblks cptr
                                             >> go (blks - rblks) g' cptr
                               | otherwise   = apply g' blks cptr
          initializeMemory g1 iv1
          allocaBuffer rblks (go nblks1 g1)

        benchAction = withMemory $ (process iv nblks g)
