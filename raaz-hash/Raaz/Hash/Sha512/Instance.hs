{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha512.Instance (sha512CompressSingle) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha512.CPortable ()


----------------------------- SHA512 -------------------------------------------

instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = CGadget SHA512 (MemoryCell SHA512)
  type Reference SHA512   = HGadget SHA512 (MemoryCell SHA512)

instance Hash SHA512 where
  defaultKey _ = SHA512 $ VU.fromList [ 0x6a09e667f3bcc908
                                      , 0xbb67ae8584caa73b
                                      , 0x3c6ef372fe94f82b
                                      , 0xa54ff53a5f1d36f1
                                      , 0x510e527fade682d1
                                      , 0x9b05688c2b3e6c1f
                                      , 0x1f83d9abfb41bd6b
                                      , 0x5be0cd19137e2179
                                      ]

  hashDigest = id

instance InitializableMemory (HGadget SHA512 (MemoryCell SHA512)) where
  type IV (HGadget SHA512 (MemoryCell SHA512)) = SHA512
  initializeMemory (HGadget mc) = cellPoke mc

instance FinalizableMemory (HGadget SHA512 (MemoryCell SHA512)) where
  type FV (HGadget SHA512 (MemoryCell SHA512)) = SHA512
  finalizeMemory (HGadget mc) = cellPeek mc

instance Gadget (HGadget SHA512 (MemoryCell SHA512)) where
  type PrimitiveOf (HGadget SHA512 (MemoryCell SHA512)) = SHA512
  apply (HGadget mc) n cptr = do
    initial <- cellPeek mc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellPoke mc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA512 (MemoryCell SHA512))
