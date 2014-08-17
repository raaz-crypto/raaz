{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Hash.Sha384.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives

import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..)     )
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

instance Gadget (CGadget SHA384) where
  type PrimitiveOf (CGadget SHA384) = SHA384
  type MemoryOf (CGadget SHA384)    = CryptoCell SHA512
  newGadgetWithMemory               = return . CGadget
  getMemory (CGadget m)             = m
  apply (CGadget cc) n              = sha512Compress cc n'
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)

instance PaddableGadget (CGadget SHA384)
