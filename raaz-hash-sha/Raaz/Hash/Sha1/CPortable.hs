{-|

Portable C implementation of SHA1 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha1/portable.c  #-}

module Raaz.Hash.Sha1.CPortable
       ( CPortable
       ) where


import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

import Raaz.Hash.Sha1.Type

-- | Portable C implementation
data CPortable

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: Ptr SHA1 -> Int -> CryptoPtr -> IO ()

sha1Compress :: SHA1 -> Int -> CryptoPtr -> IO SHA1
{-# INLINE sha1Compress #-}
sha1Compress sha1 nblocks buffer = alloca go
  where go ptr = do poke ptr sha1
                    c_sha1_compress ptr nblocks buffer
                    peek ptr

instance Implementation CPortable where
  type PrimitiveOf CPortable = SHA1
  newtype Cxt CPortable = SHA1Cxt SHA1
  process (SHA1Cxt sha1) nblocks buf = fmap SHA1Cxt $ sha1Compress sha1 n buf
      where n = fromEnum nblocks

instance HashImplementation CPortable where
  startHashCxt = SHA1Cxt $ SHA1 0x67452301
                                0xefcdab89
                                0x98badcfe
                                0x10325476
                                0xc3d2e1f0
  finaliseHash (SHA1Cxt h) = h
