{-|

Portable C implementation of SHA1 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/hash/sha1/portable.c  #-}

module Raaz.Hash.Sha1.CPortable () where

import Control.Applicative ( (<$>) )

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types

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
  initialize (CGadget cc) (SHA1Cxt sha1) = cellPoke cc sha1
  finalize (CGadget cc) = SHA1Cxt <$> cellPeek cc
  apply (CGadget cc)    = sha1Compress cc

instance PaddableGadget (CGadget SHA1)
