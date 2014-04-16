{-# LANGUAGE BangPatterns #-}
module Raaz.Number.Util
       ( numberOfBits
         -- * Integer to Bytestring conversion
       , i2osp
       , os2ip
         -- * Timing independed operations
       , safeAnd
       , safeAll
       , safeAllBS
       ) where

import           Data.List       (foldl')
import           Data.Word
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import           Raaz.Types


-- | Number of Bits required to represent the number
numberOfBits :: Integral i => i -> BITS Int
numberOfBits i = go i 0
  where
    go 0 !m = m
    go !n !m = go (n `div` 2) (m+1)
{-# SPECIALIZE numberOfBits :: Int -> BITS Int #-}
{-# SPECIALIZE numberOfBits :: Integer -> BITS Int #-}

-- | Timing attack resistant function to check if all elements are True.
safeAll :: [Bool] -> Bool
safeAll = foldl' safeAnd True

-- | Determines if all elements of the ByteString satisfy the
-- predicate in a timing attack resistant manner.
safeAllBS :: (Word8 -> Bool) -> ByteString -> Bool
safeAllBS f = safeAll . map f . BS.unpack

-- | Safe `&&` without shortcircuiting to make it data independent.
safeAnd :: Bool -> Bool -> Bool
safeAnd True True = True
safeAnd True False = False
safeAnd False True = False
safeAnd False False = False

-- | Converts non-negative Integer to ByteString
i2osp :: Integer          -- ^ Non Negative Integer
      -> BYTES Int        -- ^ Intended Length of Octet Stream
      -> ByteString       -- ^ ByteString of given Length
i2osp x xLen = base256 x
  where
    base256 = BS.reverse . fst . BS.unfoldrN (fromIntegral xLen) with
    with b | b <= 0    = Just (0,0)
           | otherwise = Just (fromIntegral r, q)
      where (q,r) = b `quotRem` 256
{-# INLINE i2osp #-}


-- | Converts Octet String to non-negative integer
os2ip :: ByteString  -- ^ ByteString
      -> Integer     -- ^ Non Negative Integer
os2ip = BS.foldl with 0
  where
    with o w = o * 256 + fromIntegral w
{-# INLINE os2ip #-}
