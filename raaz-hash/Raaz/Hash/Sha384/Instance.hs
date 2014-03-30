{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance () where

import Control.Applicative ((<$>))
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type ( SHA512(..) )
import Raaz.Hash.Sha512.Instance
import Raaz.Hash.Sha384.CPortable ()


----------------------------- SHA384 -------------------------------------------

instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = CGadget SHA384
  type Reference SHA384   = HGadget SHA384

instance Hash SHA384 where
  cxtToHash (SHA384Cxt h) = sha512Tosha384 h
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = SHA384 h0 h1 h2 h3 h4 h5

instance Gadget (HGadget SHA384) where
  type PrimitiveOf (HGadget SHA384) = SHA384
  type MemoryOf (HGadget SHA384) = CryptoCell SHA512
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA384Cxt sha1) = cellStore cc sha1
  finalize (HGadget cc) = SHA384Cxt <$> cellLoad cc
  apply (HGadget cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA384)
