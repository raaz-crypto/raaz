{-|

Portable C implementation of SHA1 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/hash/sha1/portable.c  #-}

module Raaz.Hash.Sha1.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types

import Raaz.Hash.Sha1.Type

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: Pointer -> Int -> Pointer -> IO ()

sha1Compress :: MemoryCell SHA1 -> BLOCKS SHA1 -> Pointer -> IO ()
{-# INLINE sha1Compress #-}
sha1Compress mc nblocks buffer = withCell mc action
  where action ptr = c_sha1_compress ptr n buffer
        n = fromEnum nblocks

instance InitializableMemory (CGadget SHA1 (MemoryCell SHA1)) where
  type IV (CGadget SHA1 (MemoryCell SHA1)) = SHA1
  initializeMemory (CGadget mc) = cellPoke mc

instance FinalizableMemory (CGadget SHA1 (MemoryCell SHA1)) where
  type FV (CGadget SHA1 (MemoryCell SHA1)) = SHA1
  finalizeMemory (CGadget mc) = cellPeek mc

instance Gadget (CGadget SHA1 (MemoryCell SHA1)) where
  type PrimitiveOf (CGadget SHA1 (MemoryCell SHA1)) = SHA1
  apply (CGadget mc) = sha1Compress mc

instance PaddableGadget (CGadget SHA1 (MemoryCell SHA1))
