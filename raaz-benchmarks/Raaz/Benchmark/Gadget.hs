{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Benchmark.Gadget
       ( benchGadget
       , benchGadgetMany
       ) where

import Criterion.Main
import Data.ByteString (ByteString)
import Data.Typeable


import Raaz.Memory
import Raaz.Primitives

import Raaz.Util.Gadget

-- | Measures the performance of a gadget on the given
-- bytestring. Bytestring is assumed to be multiple of blockSize.
benchGadget  :: ( Gadget g, Typeable (PrimitiveOf g) )
             => g                  -- ^ Gadget
             -> String             -- ^ Gadget name
             -> IV (PrimitiveOf g) -- ^ Gadget IV
             -> ByteString         -- ^ Bytestring to be processed
             -> Benchmark
benchGadget g' gname iv bs = bench name $ do
  g <- createGadget g'
  initialize g iv
  applyOnByteSource g bs
  _ <- finalize g
  return ()
  where
    getPrim :: Gadget g => g -> PrimitiveOf g
    getPrim _ = undefined
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget =<< newMemory
    name = concat [ "Primitive: "
                  , show (typeOf $ getPrim g')
                  , " => Gadget: "
                  , gname
                  ]

-- | Perform benchmarking on multiple bytestrings.
benchGadgetMany :: ( Gadget g, Typeable (PrimitiveOf g) )
             => g                  -- ^ Gadget
             -> String             -- ^ Gadget name
             -> IV (PrimitiveOf g) -- ^ Gadget IV
             -> [ByteString]       -- ^ Bytestring to be processed
             -> [Benchmark]
benchGadgetMany g gname iv bss = map (benchGadget g gname iv) bss
