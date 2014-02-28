{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha512.Instance (sha512Compress) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Util.Ptr
import Raaz.Types

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha512.CPortable ()


----------------------------- SHA512 -------------------------------------------

instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = CGadget SHA512
  type Reference SHA512   = HGadget SHA512

instance Hash SHA512

sha512Compress :: CryptoCell SHA512 -> BLOCKS SHA512 -> CryptoPtr -> IO ()
sha512Compress cc n cptr = do
  initial <- cellLoad cc
  final <- fst <$> foldM moveAndHash (initial,cptr) [1..n]
  cellStore cc final
    where
      sz = blockSize (undefined :: SHA512)
      moveAndHash (cxt,ptr) _ = do newCxt <- sha512CompressSingle cxt ptr
                                   return (newCxt, ptr `movePtr` sz)
{-# INLINE sha512Compress #-}

instance Gadget (HGadget SHA512) where
  type PrimitiveOf (HGadget SHA512) = SHA512
  type MemoryOf (HGadget SHA512) = CryptoCell SHA512
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA512IV sha1) = cellStore cc sha1
  finalize (HGadget cc) = cellLoad cc
  apply (HGadget cc) = sha512Compress cc
