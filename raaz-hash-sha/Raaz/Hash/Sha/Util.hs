module Raaz.Hash.Sha.Util
    ( padLength64, padding64
    , padLength128,padding128
    ) where

import qualified Data.ByteString as B
import Data.Word
import Foreign.Storable(Storable(..))

import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

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
