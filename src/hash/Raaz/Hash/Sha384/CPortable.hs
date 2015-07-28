{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Hash.Sha384.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..)     )
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

instance InitializableMemory (CGadget SHA384 (MemoryCell SHA512)) where
  type IV (CGadget SHA384 (MemoryCell SHA512)) = SHA512
  initializeMemory (CGadget mc) = cellPoke mc

instance FinalizableMemory (CGadget SHA384 (MemoryCell SHA512)) where
  type FV (CGadget SHA384 (MemoryCell SHA512)) = SHA512
  finalizeMemory (CGadget mc) = cellPeek mc

instance Gadget (CGadget SHA384 (MemoryCell SHA512)) where
  type PrimitiveOf (CGadget SHA384 (MemoryCell SHA512)) = SHA384
  apply (CGadget mc) n = sha512Compress mc n'
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)

instance PaddableGadget (CGadget SHA384 (MemoryCell SHA512))
