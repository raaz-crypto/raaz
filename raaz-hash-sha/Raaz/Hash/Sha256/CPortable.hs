{-|

Portable C implementation of SHA256 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha256/portable.c  #-}

module Raaz.Hash.Sha256.CPortable
       ( CPortable
       , sha256Compress
       ) where


import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

import Raaz.Hash.Sha256.Type

-- | Portable C implementation
data CPortable

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Ptr SHA256 -> Int -> CryptoPtr -> IO ()

sha256Compress :: SHA256 -> Int -> CryptoPtr -> IO SHA256
{-# INLINE sha256Compress #-}
sha256Compress sha256 nblocks buffer = alloca go
  where go ptr = do poke ptr sha256
                    c_sha256_compress ptr nblocks buffer
                    peek ptr

instance Implementation CPortable where
  type PrimitiveOf CPortable = SHA256
  newtype Cxt CPortable = SHA256Cxt SHA256
  process (SHA256Cxt sha256) nblocks buf = fmap SHA256Cxt $ sha256Compress sha256 n buf
      where n = fromEnum nblocks

instance HashImplementation CPortable where
  startHashCxt = SHA256Cxt $ SHA256 0x6a09e667
                                    0xbb67ae85
                                    0x3c6ef372
                                    0xa54ff53a
                                    0x510e527f
                                    0x9b05688c
                                    0x1f83d9ab
                                    0x5be0cd19
  finaliseHash (SHA256Cxt h) = h
