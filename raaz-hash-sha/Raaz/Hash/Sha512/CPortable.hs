{-|

Portable C implementation of SHA512 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha512/portable.c  #-}

module Raaz.Hash.Sha512.CPortable
       ( CPortable
       , sha512Compress
       ) where


import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

import Raaz.Hash.Sha512.Type

-- | Portable C implementation
data CPortable

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: Ptr SHA512 -> Int -> CryptoPtr -> IO ()

sha512Compress :: SHA512 -> Int -> CryptoPtr -> IO SHA512
{-# INLINE sha512Compress #-}
sha512Compress sha512 nblocks buffer = alloca go
  where go ptr = do poke ptr sha512
                    c_sha512_compress ptr nblocks buffer
                    peek ptr

instance Implementation CPortable where
  type PrimitiveOf CPortable = SHA512
  newtype Cxt CPortable = SHA512Cxt SHA512
  process (SHA512Cxt sha512) nblocks buf = fmap SHA512Cxt $ sha512Compress sha512 n buf
      where n = fromEnum nblocks

instance HashImplementation CPortable where
  startHashCxt = SHA512Cxt $ SHA512 0x6a09e667f3bcc908
                                    0xbb67ae8584caa73b
                                    0x3c6ef372fe94f82b
                                    0xa54ff53a5f1d36f1
                                    0x510e527fade682d1
                                    0x9b05688c2b3e6c1f
                                    0x1f83d9abfb41bd6b
                                    0x5be0cd19137e2179
  finaliseHash (SHA512Cxt h) = h
