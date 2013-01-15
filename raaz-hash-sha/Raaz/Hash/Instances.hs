{-

This module defines the hash instances for different hashes.

-}
{-# LANGUAGE TypeFamilies #-}

module Raaz.Hash.Instances where

import Control.Applicative ((<$>))
import qualified Data.ByteString as B
import Data.Word
import Foreign.Storable(Storable(..))

import Raaz.Hash
import Raaz.Hash.Sha
import Raaz.Hash.Sha.Ref.Sha1
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

firstPadByte :: Word8
firstPadByte = 128

-- | Number of bytes in the padding for the first pad byte and the
-- length encoding for a 64-bit length appended hash like SHA1
extra64  :: BYTES Int
extra64  = BYTES $ 1 + sizeOf (undefined :: Word64)

-- | Padding length for a 64-bit length appended hash like SHA1.
padLength64 :: Hash h => h -> BITS Word64 -> BYTES Int
{-# INLINE padLength64 #-}
padLength64 h l | r >= extra64 = r
                | otherwise    = r + blockSize h
  where lb :: BYTES Int
        lb    = cryptoCoerce l `rem` blockSize h
        r     = blockSize h - lb

-- | Padding string for a 64-bit length appended hash like SHA1.
padding64 :: Hash h => h -> BITS Word64 -> B.ByteString
padding64 h l = B.concat [ B.singleton firstPadByte
                         , B.replicate zeros 0
                         , toByteString lBits
                         ]
     where r      = padLength h l :: BYTES Int
           zeros  = fromIntegral $ r - extra64
           lBits  = cryptoCoerce l :: BITS Word64BE
