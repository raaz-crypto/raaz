{-# LANGUAGE BangPatterns #-}
module Raaz.Number.Util where

import           Data.Bits
import           Data.List       (foldl')
import           Data.Word
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import           Raaz.Types

-- | Modular exponentiation @x^n mod m@
powModulo :: Integer -> Integer -> Integer -> Integer
powModulo x n m = go x n 1
 where
  go _   0 !result = result
  go !b !e !result = go b' e' result'
   where
    !b'      = (b * b) `rem` m
    !e'      = e `shiftR` 1
    !result' | testBit e 0 = (result * b) `rem` m
             | otherwise   = result

-- | Number of Bits required to represent the number
numberOfBits :: Integral i => i -> BITS Int
numberOfBits i = go i 0
  where
    go 0 !m = m
    go !n !m = go (n `div` 2) (m+1)
{-# SPECIALIZE numberOfBits :: Int -> BITS Int #-}
{-# SPECIALIZE numberOfBits :: Integer -> BITS Int #-}

-- | A byte with first @i@ bits as 1 and rest 0
mask :: BITS Int -> Word8
mask 0 = 0x00
mask 1 = 0x80
mask 2 = 0xc0
mask 3 = 0xe0
mask 4 = 0xf0
mask 5 = 0xf8
mask 6 = 0xfc
mask 7 = 0xfe
mask 8 = 0xff
mask _ = error "mask: Wrong number of bits"

-- | Checks if the first n Bits of Bytestring are 0. Undefined
-- behaviour when length is less than the given number of bits.
checkZeroBits :: BITS Int -> ByteString -> Bool
checkZeroBits b bs = BS.all (== 0x00) (BS.take extraBytes bs)
                     && ((mask remBits .&. BS.index bs extraBytes) == 0x00)
  where
    (q,r) = b `quotRem` 8
    (extraBytes,remBits) = if r == 0 then (fromIntegral $ q-1,8) else (fromIntegral q,r)

-- | Zeroes out the given number of Bits from the ByteString.
zeroBits :: BITS Int -> ByteString -> ByteString
zeroBits b bs = BS.concat [ BS.replicate extraBytes 0x00
                          , BS.singleton $ complement (mask remBits) .&.
                            BS.index bs extraBytes
                          , BS.drop (extraBytes + 1) bs
                          ]
  where
    (q,r) = b `quotRem` 8
    (extraBytes,remBits) = if r == 0 then (fromIntegral $ q-1,8) else (fromIntegral q,r)

-- | Convert Bits to Bytes ceiling to the next byte. It might happen
-- that this overflows.
ceilToBytes :: BITS Int -> BYTES Int
ceilToBytes b = fromIntegral $ if r == 0 then q else q + 1
  where
    (q,r) = b `quotRem` 8

-- | Timing attack resistent function to check if all elements are True.
safeAll :: [Bool] -> Bool
safeAll = foldl' safeAnd True

-- | Safe `&&` without shortcircuiting to make it data independent.
safeAnd :: Bool -> Bool -> Bool
safeAnd True True = True
safeAnd True False = False
safeAnd False True = True
safeAnd False False = False
