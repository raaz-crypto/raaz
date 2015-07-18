{-|

Portable C implementation of SHA256 hash.

-}

{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/hash/sha256/portable.c #-}

module Raaz.Hash.Sha256.CPortable
       ( sha256Compress
       ) where

import Foreign.Ptr

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types

import Raaz.Hash.Sha256.Type

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Ptr SHA256 -> Int -> CryptoPtr -> IO ()

sha256Compress :: MemoryCell SHA256 -> BLOCKS SHA256 -> CryptoPtr -> IO ()
sha256Compress mc nblocks buffer = withCell mc action
  where action ptr = c_sha256_compress (castPtr ptr) n buffer
        n = fromEnum nblocks
{-# INLINE sha256Compress #-}

instance InitializableMemory (CGadget SHA256 (MemoryCell SHA256)) where
  type IV (CGadget SHA256 (MemoryCell SHA256)) = SHA256
  initializeMemory (CGadget mc) = cellPoke mc

instance FinalizableMemory (CGadget SHA256 (MemoryCell SHA256)) where
  type FV (CGadget SHA256 (MemoryCell SHA256)) = SHA256
  finalizeMemory (CGadget mc) = cellPeek mc

instance Gadget (CGadget SHA256 (MemoryCell SHA256)) where
  type PrimitiveOf (CGadget SHA256 (MemoryCell SHA256)) = SHA256
  apply (CGadget mc) = sha256Compress mc

instance PaddableGadget (CGadget SHA256 (MemoryCell SHA256))
