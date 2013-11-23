{-|

This module defines the hash instances for different hashes.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE EmptyDataDecls       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha1.Instance ( Ref ) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr

import Raaz.Hash.Sha1.Type
import Raaz.Hash.Sha1.Ref
import Raaz.Hash.Sha1.CPortable

----------------------------- SHA1 ---------------------------------------------

instance CryptoPrimitive SHA1 where
  type Recommended SHA1 = CPortable
  type Reference SHA1 = Ref

instance Hash SHA1 where

-- | Ref Implementation
data Ref = Ref (CryptoCell SHA1)

instance Gadget Ref where
  type PrimitiveOf Ref = SHA1
  type MemoryOf Ref = CryptoCell SHA1
  newGadget cc = return $ Ref cc
  initialize (Ref cc) (SHA1IV sha1) = cellStore cc sha1
  finalize (Ref cc) = cellLoad cc
  apply (Ref cc) n cptr = do
    initial <- cellLoad cc
    final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
    cellStore cc final
    where
      sz = blockSize (undefined :: SHA1)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha1CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)

instance SafeGadget Ref
instance HashGadget Ref
