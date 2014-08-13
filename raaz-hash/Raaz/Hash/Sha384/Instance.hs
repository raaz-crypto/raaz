{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

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

instance Hash SHA384

instance Gadget (HGadget SHA384) where
  type PrimitiveOf (HGadget SHA384) = SHA384
  type MemoryOf (HGadget SHA384) = CryptoCell SHA512
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA384Cxt sha1) = cellPoke cc sha1
  finalize (HGadget cc) = SHA384Cxt <$> cellPeek cc
  apply (HGadget cc) n cptr = do
    initial <- cellPeek cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellPoke cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance PaddableGadget (HGadget SHA384)
