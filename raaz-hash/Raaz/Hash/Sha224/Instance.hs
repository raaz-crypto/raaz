{-|

This module defines the hash instances for sha224 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha224.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

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

instance Hash SHA224

instance Gadget (HGadget SHA224) where
  type PrimitiveOf (HGadget SHA224) = SHA224
  type MemoryOf (HGadget SHA224) = CryptoCell SHA256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA224Cxt sha1) = cellStore cc sha1
  finalize (HGadget cc) = SHA224Cxt <$> cellLoad cc
  apply (HGadget cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA224)
