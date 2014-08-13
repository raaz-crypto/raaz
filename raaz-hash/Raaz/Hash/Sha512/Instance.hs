{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha512.Instance (sha512CompressSingle) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha512.CPortable ()


----------------------------- SHA512 -------------------------------------------

instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = CGadget SHA512
  type Reference SHA512   = HGadget SHA512

instance Hash SHA512

instance Gadget (HGadget SHA512) where
  type PrimitiveOf (HGadget SHA512) = SHA512
  type MemoryOf (HGadget SHA512) = CryptoCell SHA512
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA512Cxt sha1) = cellStore cc sha1
  finalize (HGadget cc) = SHA512Cxt <$> cellPeek cc
  apply (HGadget cc) n cptr = do
    initial <- cellPeek cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA512)
