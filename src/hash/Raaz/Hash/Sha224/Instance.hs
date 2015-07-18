{-|

This module defines the hash instances for sha224 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha224.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Instance
import Raaz.Hash.Sha224.CPortable ()


----------------------------- SHA224 -------------------------------------------

instance CryptoPrimitive SHA224 where
  type Recommended SHA224 = CGadget SHA224
  type Reference SHA224   = HGadget SHA224

instance Hash SHA224 where
  defaultCxt _ = SHA256 $ VU.fromList [ 0xc1059ed8
                                      , 0x367cd507
                                      , 0x3070dd17
                                      , 0xf70e5939
                                      , 0xffc00b31
                                      , 0x68581511
                                      , 0x64f98fa7
                                      , 0xbefa4fa4
                                      ]

  hashDigest = sha256Tosha224
    where sha256Tosha224 (SHA256 v)
              = SHA224 (VU.slice 0 7 v)

instance Gadget (HGadget SHA224) where
  type PrimitiveOf (HGadget SHA224)  = SHA224
  type MemoryOf (HGadget SHA224)     = CryptoCell SHA256
  newGadgetWithMemory                = return . HGadget
  getMemory (HGadget m)              = m
  apply (HGadget cc) n cptr          = do
    initial <- cellPeek cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellPoke cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA224)
