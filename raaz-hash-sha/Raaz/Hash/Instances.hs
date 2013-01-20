{-

This module defines the hash instances for different hashes.

-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Instances where

import Control.Applicative ((<$>))
import qualified Data.ByteString as B
import Data.Word
import Foreign.Storable(Storable(..))

import Raaz.Hash
import Raaz.Hash.Sha
import Raaz.Hash.Sha.Ref.Sha1
import Raaz.Hash.Sha.Ref.Sha256
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
