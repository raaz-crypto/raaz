{-|

This module defines the hash instances for sha256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha256.Instance (sha256Compress) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha256.CPortable ()


----------------------------- SHA256 -------------------------------------------

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = CGadget SHA256
  type Reference SHA256 = HGadget SHA256

instance Hash SHA256

sha256Compress :: CryptoCell SHA256 -> BLOCKS SHA256 -> CryptoPtr -> IO ()
sha256Compress cc n cptr = do
  initial <- cellLoad cc
  final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
  cellStore cc final
    where
      sz = blockSize (undefined :: SHA256)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha256CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)
{-# INLINE sha256Compress #-}

instance Gadget (HGadget SHA256) where
  type PrimitiveOf (HGadget SHA256) = SHA256
  type MemoryOf (HGadget SHA256) = CryptoCell SHA256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA256IV sha1) = cellStore cc sha1
  finalize (HGadget cc) = cellLoad cc
  apply (HGadget cc) = sha256Compress cc
