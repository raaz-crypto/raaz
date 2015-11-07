{-|

This module defines the hash instances for sha256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha256.Instance (sha256CompressSingle) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Types
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash

import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha256.CPortable ()


----------------------------- SHA256 -------------------------------------------

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = CGadget SHA256 (MemoryCell SHA256)
  type Reference SHA256 = HGadget SHA256 (MemoryCell SHA256)

instance Hash SHA256 where
  defaultKey _ = SHA256 $ VU.fromList [ 0x6a09e667
                                      , 0xbb67ae85
                                      , 0x3c6ef372
                                      , 0xa54ff53a
                                      , 0x510e527f
                                      , 0x9b05688c
                                      , 0x1f83d9ab
                                      , 0x5be0cd19
                                      ]

  hashDigest = id

instance InitializableMemory (HGadget SHA256 (MemoryCell SHA256)) where
  type IV (HGadget SHA256 (MemoryCell SHA256)) = SHA256
  initializeMemory (HGadget mc) = cellPoke mc

instance FinalizableMemory (HGadget SHA256 (MemoryCell SHA256)) where
  type FV (HGadget SHA256 (MemoryCell SHA256)) = SHA256
  finalizeMemory (HGadget mc) = cellPeek mc

instance Gadget (HGadget SHA256 (MemoryCell SHA256)) where
  type PrimitiveOf (HGadget SHA256 (MemoryCell SHA256)) = SHA256
  apply (HGadget mc) n cptr = do
    initial <- cellPeek mc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellPoke mc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA256 (MemoryCell SHA256))
