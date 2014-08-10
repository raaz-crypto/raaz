{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives

import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Type      ( SHA256(..)     )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

instance Gadget (CGadget SHA224) where
  type PrimitiveOf (CGadget SHA224)          = SHA224
  type MemoryOf (CGadget SHA224)             = CryptoCell SHA256
  newGadgetWithMemory                        = return . CGadget
  getMemory (CGadget m)                      = m
  apply (CGadget cc) n                       = sha256Compress cc n'
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)

instance PaddableGadget (CGadget SHA224)
