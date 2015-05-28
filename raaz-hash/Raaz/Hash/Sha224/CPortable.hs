{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives

import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Type      ( SHA256(..)     )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

instance InitializableMemory (CGadget SHA224 (MemoryCell SHA256)) where
  type IV (CGadget SHA224 (MemoryCell SHA256)) = SHA256
  initializeMemory (CGadget mc) = cellPoke mc

instance FinalizableMemory (CGadget SHA224 (MemoryCell SHA256)) where
  type FV (CGadget SHA224 (MemoryCell SHA256)) = SHA256
  finalizeMemory (CGadget mc) = cellPeek mc

instance Gadget (CGadget SHA224 (MemoryCell SHA256)) where
  type PrimitiveOf (CGadget SHA224 (MemoryCell SHA256)) = SHA224
  apply (CGadget mc) n = sha256Compress mc n'
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)

instance PaddableGadget (CGadget SHA224 (MemoryCell SHA256))
