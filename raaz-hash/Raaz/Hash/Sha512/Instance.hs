{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha512.Instance ( Ref ) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha512.CPortable


----------------------------- SHA512 -------------------------------------------

instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = CPortable
  type Reference SHA512   = Ref

instance Hash SHA512 where

-- | Ref Implementation
data Ref = Ref (CryptoCell SHA512)

instance Gadget Ref where
  type PrimitiveOf Ref = SHA512
  type MemoryOf Ref = CryptoCell SHA512
  newGadget cc = return $ Ref cc
  initialize (Ref cc) (SHA512IV sha1) = cellStore cc sha1
  finalize (Ref cc) = cellLoad cc
  apply (Ref cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance SafeGadget Ref
instance HashGadget Ref
