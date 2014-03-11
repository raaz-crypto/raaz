{-|

Portable C implementation of SHA256 hash.

-}

{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE EmptyDataDecls            #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/hash/sha256/portable.c #-}

module Raaz.Hash.Sha256.CPortable
       ( sha256Compress
       ) where


import Foreign.Ptr

import Raaz.Memory
import Raaz.Primitives
import Raaz.Types

import Raaz.Hash.Sha256.Type

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Ptr SHA256 -> Int -> CryptoPtr -> IO ()

sha256Compress :: CryptoCell SHA256 -> BLOCKS SHA256 -> CryptoPtr -> IO ()
sha256Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha256_compress (castPtr ptr) n buffer
        n = fromEnum nblocks
{-# INLINE sha256Compress #-}

instance Gadget (CGadget SHA256) where
  type PrimitiveOf (CGadget SHA256) = SHA256
  type MemoryOf (CGadget SHA256) = CryptoCell SHA256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA256IV sha1) = cellStore cc sha1
  finalize (CGadget cc) = cellLoad cc
  apply (CGadget cc) n cptr = sha256Compress cc n cptr

instance PaddableGadget (CGadget SHA256)
