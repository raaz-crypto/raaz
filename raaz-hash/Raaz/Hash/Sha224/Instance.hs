{-|

This module defines the hash instances for sha224 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha224.Instance (CPortable, Ref) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr


import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha224.CPortable


----------------------------- SHA224 -------------------------------------------

instance CryptoPrimitive SHA224 where
  type Recommended SHA224 = CPortable
  type Reference SHA224   = Ref

instance Hash SHA224 where

-- | Ref Implementation
data Ref = Ref (CryptoCell SHA256)

instance Gadget Ref where
  type PrimitiveOf Ref = SHA224
  type MemoryOf Ref = CryptoCell SHA256
  newGadget cc = return $ Ref cc
  initialize (Ref cc) (SHA224IV sha1) = cellStore cc sha1
  finalize (Ref cc) = sha256Tosha224 <$> cellLoad cc
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
  apply (Ref cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)
