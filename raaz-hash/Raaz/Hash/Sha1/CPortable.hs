{-|

Portable C implementation of SHA1 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/hash/sha1/portable.c  #-}

module Raaz.Hash.Sha1.CPortable () where

import Raaz.Memory
import Raaz.Primitives
import Raaz.Types

import Raaz.Hash.Sha1.Type

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: CryptoPtr -> Int -> CryptoPtr -> IO ()

sha1Compress :: CryptoCell SHA1 -> BLOCKS SHA1 -> CryptoPtr -> IO ()
{-# INLINE sha1Compress #-}
sha1Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha1_compress ptr n buffer
        n = fromEnum nblocks

instance Gadget (CGadget SHA1) where
  type PrimitiveOf (CGadget SHA1) = SHA1
  type MemoryOf (CGadget SHA1) = CryptoCell SHA1
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA1IV sha1) = cellStore cc sha1
  finalize (CGadget cc) = cellLoad cc
  apply (CGadget cc) n cptr = sha1Compress cc n cptr
