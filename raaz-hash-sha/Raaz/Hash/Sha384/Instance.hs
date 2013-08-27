{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance ( Ref ) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type ( SHA512(..) )
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha384.CPortable


----------------------------- SHA384 -------------------------------------------

instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = CPortable
  type Reference SHA384   = Ref

instance Hash SHA384 where

-- | Ref Implementation
data Ref = Ref (CryptoCell SHA512)

instance Gadget Ref where
  type PrimitiveOf Ref = SHA384
  type MemoryOf Ref = CryptoCell SHA512
  newGadget cc = return $ Ref cc
  initialize (Ref cc) (SHA384IV sha1) = cellStore cc sha1
  finalize (Ref cc) = sha512Tosha384 <$> cellLoad cc
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = SHA384 h0 h1 h2 h3 h4 h5

instance SafeGadget Ref where
  applySafe (Ref cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance HashGadget Ref where
