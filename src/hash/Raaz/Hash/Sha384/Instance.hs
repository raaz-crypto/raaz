{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..) )
import Raaz.Hash.Sha512.Instance
import Raaz.Hash.Sha384.CPortable (            )


----------------------------- SHA384 -------------------------------------------

instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = CGadget SHA384
  type Reference SHA384   = HGadget SHA384

instance Hash SHA384 where
  defaultCxt _ = SHA512 $ VU.fromList [ 0xcbbb9d5dc1059ed8
                                      , 0x629a292a367cd507
                                      , 0x9159015a3070dd17
                                      , 0x152fecd8f70e5939
                                      , 0x67332667ffc00b31
                                      , 0x8eb44a8768581511
                                      , 0xdb0c2e0d64f98fa7
                                      , 0x47b5481dbefa4fa4
                                      ]

  hashDigest = sha512Tosha384
    where sha512Tosha384 (SHA512 v)
            = SHA384 (VU.slice 0 6 v)

instance Gadget (HGadget SHA384) where
  type PrimitiveOf (HGadget SHA384)  = SHA384
  type MemoryOf (HGadget SHA384)     = CryptoCell SHA512
  getMemory (HGadget m)              = m
  newGadgetWithMemory                = return . HGadget
  apply (HGadget cc) n cptr          = do
    initial <- cellPeek cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellPoke cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA384)
