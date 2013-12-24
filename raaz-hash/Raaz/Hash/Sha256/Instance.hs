{-|

This module defines the hash instances for sha256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha256.Instance (CPortable, Ref) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha256.CPortable


----------------------------- SHA256 -------------------------------------------

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = CPortable
  type Reference SHA256 = Ref

instance Hash SHA256 where

-- | Ref Implementation
data Ref = Ref (CryptoCell SHA256)

instance Gadget Ref where
  type PrimitiveOf Ref = SHA256
  type MemoryOf Ref = CryptoCell SHA256
  newGadget cc = return $ Ref cc
  initialize (Ref cc) (SHA256IV sha1) = cellStore cc sha1
  finalize (Ref cc) = cellLoad cc
  apply (Ref cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)
