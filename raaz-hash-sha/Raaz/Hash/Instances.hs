{-

This module defines the hash instances for different hashes.

-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Instances () where

import Control.Applicative ((<$>))
import qualified Data.ByteString as B
import Data.Word
import Foreign.Storable(Storable(..))

import Raaz.Hash
import Raaz.Hash.Sha
import Raaz.Hash.Sha.Ref.Sha1
import Raaz.Hash.Sha.Ref.Sha256
import Raaz.Hash.Sha.Ref.Sha512
import Raaz.Primitives
import Raaz.Types

instance Hash SHA1 where
  newtype Cxt SHA1 = SHA1Cxt SHA1

  startCxt _ = SHA1Cxt $ SHA1 0x67452301
                              0xefcdab89
                              0x98badcfe
                              0x10325476
                              0xc3d2e1f0
  finaliseHash (SHA1Cxt h) = h

  maxAdditionalBlocks _ = 1

  padLength = padLength64
  padding   = padding64
  compressSingle (SHA1Cxt cxt) ptr = SHA1Cxt <$> sha1CompressSingle cxt ptr

instance Hash SHA224 where
  newtype Cxt SHA224 = SHA224Cxt SHA256

  startCxt _ = SHA224Cxt $ SHA256 0xc1059ed8
                                  0x367cd507
                                  0x3070dd17
                                  0xf70e5939
                                  0xffc00b31
                                  0x68581511
                                  0x64f98fa7
                                  0xbefa4fa4

  finaliseHash (SHA224Cxt h) = sha256Tosha224 h
   where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
                       = SHA224 h0 h1 h2 h3 h4 h5 h6

  maxAdditionalBlocks _ = 1

  padLength = padLength64
  padding   = padding64
  compressSingle (SHA224Cxt cxt) ptr = SHA224Cxt <$> sha256CompressSingle cxt ptr

instance Hash SHA256 where
  newtype Cxt SHA256 = SHA256Cxt SHA256

  startCxt _ = SHA256Cxt $ SHA256 0x6a09e667
                                  0xbb67ae85
                                  0x3c6ef372
                                  0xa54ff53a
                                  0x510e527f
                                  0x9b05688c
                                  0x1f83d9ab
                                  0x5be0cd19

  finaliseHash (SHA256Cxt h) = h

  maxAdditionalBlocks _ = 1

  padLength = padLength64
  padding   = padding64
  compressSingle (SHA256Cxt cxt) ptr = SHA256Cxt <$> sha256CompressSingle cxt ptr

instance Hash SHA512 where
  newtype Cxt SHA512 = SHA512Cxt SHA512

  startCxt _ = SHA512Cxt $ SHA512 0x6a09e667f3bcc908
                                  0xbb67ae8584caa73b
                                  0x3c6ef372fe94f82b
                                  0xa54ff53a5f1d36f1
                                  0x510e527fade682d1
                                  0x9b05688c2b3e6c1f
                                  0x1f83d9abfb41bd6b
                                  0x5be0cd19137e2179

  finaliseHash (SHA512Cxt h) = h

  maxAdditionalBlocks _ = 1

  padLength = padLength128
  padding   = padding128
  compressSingle (SHA512Cxt cxt) ptr = SHA512Cxt <$> sha512CompressSingle cxt ptr

instance Hash SHA384 where
  newtype Cxt SHA384 = SHA384Cxt SHA512

  startCxt _ = SHA384Cxt $ SHA512 0xcbbb9d5dc1059ed8
                                  0x629a292a367cd507
                                  0x9159015a3070dd17
                                  0x152fecd8f70e5939
                                  0x67332667ffc00b31
                                  0x8eb44a8768581511
                                  0xdb0c2e0d64f98fa7
                                  0x47b5481dbefa4fa4

  finaliseHash (SHA384Cxt h) = sha512Tosha384 h
   where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
                      = (SHA384 h0 h1 h2 h3 h4 h5)

  maxAdditionalBlocks _ = 1

  padLength = padLength128
  padding   = padding128
  compressSingle (SHA384Cxt cxt) ptr = SHA384Cxt <$> sha512CompressSingle cxt ptr


firstPadByte :: Word8
firstPadByte = 128

-- | Number of bytes in the padding for the first pad byte and the
-- length encoding for a 64-bit length appended hash like
-- SHA1, SHA224, SHA256.
extra64  :: BYTES Int
extra64  = BYTES $ 1 + sizeOf (undefined :: Word64)

-- | Padding length for a 64-bit length appended hash like SHA1,
-- SHA224, SHA256.
padLength64 :: Hash h => h -> BITS Word64 -> BYTES Int
{-# INLINE padLength64 #-}
padLength64 h l | r >= extra64 = r
                | otherwise    = r + blockSize h
  where lb :: BYTES Int
        lb    = cryptoCoerce l `rem` blockSize h
        r     = blockSize h - lb

-- | Padding string for a 64-bit length appended hash like SHA1,
-- SHA224, SHA256.
padding64 :: Hash h => h -> BITS Word64 -> B.ByteString
padding64 h l = B.concat [ B.singleton firstPadByte
                         , B.replicate zeros 0
                         , toByteString lBits
                         ]
     where r      = padLength h l :: BYTES Int
           zeros  = fromIntegral $ r - extra64
           lBits  = cryptoCoerce l :: BITS Word64BE

-- | Number of bytes in the padding for the first pad byte and the
-- length encoding for a 128-bit length appended hash like
-- SHA384,SHA512.
extra128 :: BYTES Int
extra128 = BYTES $ 1 + 2*sizeOf (undefined :: Word64)

-- | Padding length for a 128-bit length appended hash like
-- SHA384,SHA512.
padLength128 :: Hash h => h -> BITS Word64 -> BYTES Int
{-# INLINE padLength128 #-}
padLength128 h l | r >= extra128 = r
                 | otherwise     = r + blockSize h
  where lb :: BYTES Int
        lb    = cryptoCoerce l `rem` blockSize h
        r     = blockSize h - lb

-- | Padding string for a 128-bit length appended hash like
-- SHA384,SHA512.
padding128 :: Hash h => h -> BITS Word64 -> B.ByteString
padding128 h l = B.concat [ B.singleton firstPadByte
                          , B.replicate totalZeros 0
                          , toByteString lBits
                          ]
     where r            = padLength h l :: BYTES Int
           BYTES zeros  = r - extra128
           totalZeros   = zeros + sizeOf (undefined :: Word64BE)
           lBits        = cryptoCoerce l :: BITS Word64BE
