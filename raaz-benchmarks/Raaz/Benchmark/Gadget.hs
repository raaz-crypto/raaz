{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Benchmark.Gadget
       ( benchGadget
       , benchGadgetWith
       ) where

import Criterion.Main
import Data.Typeable


import Raaz.Memory
import Raaz.Primitives
import Raaz.Types
import Raaz.Util.Ptr

-- | Measures the performance of a gadget on the given buffer.
benchGadget  :: ( Gadget g, Typeable (PrimitiveOf g) )
             => g                      -- ^ Gadget
             -> String                 -- ^ Gadget name
             -> IV (PrimitiveOf g)     -- ^ Gadget IV
             -> CryptoPtr              -- ^ Buffer on which to benchmark
             -> BLOCKS (PrimitiveOf g) -- ^ Size of Buffer
             -> Benchmark
benchGadget g' gname iv cptr nblks = bench name $ applyGadget g' iv cptr nblks
  where
    name = getName g' gname

benchGadgetWith :: ( Gadget g, Typeable (PrimitiveOf g) )
                => g                      -- ^ Gadget
                -> String                 -- ^ Gadget name
                -> IV (PrimitiveOf g)     -- ^ Gadget IV
                -> BLOCKS (PrimitiveOf g) -- ^ Size of random buffer which will be allocated
                -> Benchmark
benchGadgetWith g' gname iv nblks = bench name $ allocaBuffer nblks go
  where
    go cptr = applyGadget g' iv cptr nblks
    name = getName g' gname

applyGadget :: ( Gadget g )
            => g
            -> IV (PrimitiveOf g)
            -> CryptoPtr
            -> BLOCKS (PrimitiveOf g)
            -> IO ()
applyGadget g' iv cptr nblks = do
  g <- createGadget g'
  initialize g iv
  apply g nblks cptr
  _ <- finalize g
  return ()
  where
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget =<< newMemory

getName :: ( Gadget g, Typeable (PrimitiveOf g) )
        => g
        -> String
        -> String
getName g gname = name
  where
    getPrim :: Gadget g => g -> PrimitiveOf g
    getPrim _ = undefined
    name = concat [ "Primitive: "
                  , show (typeOf $ getPrim g)
                  , " => Gadget: "
                  , gname
                  ]
