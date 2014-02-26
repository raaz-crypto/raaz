{-|

This module defines the hash instances for sha256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha256.Instance (sha256CompressSingle) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha256.CPortable ()


----------------------------- SHA256 -------------------------------------------

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = CGadget SHA256
  type Reference SHA256 = HGadget SHA256

instance Hash SHA256 where
  cxtToHash (SHA256Cxt h) = h

instance Gadget (HGadget SHA256) where
  type PrimitiveOf (HGadget SHA256) = SHA256
  type MemoryOf (HGadget SHA256) = CryptoCell SHA256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA256Cxt sha1) = cellStore cc sha1
  finalize (HGadget cc) = SHA256Cxt <$> cellLoad cc
  apply (HGadget cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA256)
