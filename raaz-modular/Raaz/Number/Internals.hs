{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
module Raaz.Number.Internals
       ( Word128
       ) where

import           Control.Applicative
import           Data.Bits
import qualified Data.ByteString     as BS
import           Data.Monoid
import           Data.Word
import           Foreign.Ptr
import           Foreign.Storable

import           Raaz.Types
import           Raaz.Parse.Unsafe
import           Raaz.Write.Unsafe


import           Raaz.Number.Modular
import           Raaz.Number.Util

-- | 128 Bit Word
newtype Word128 = Word128 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 128 Bits
narrowWord128 :: Integer -> Integer
narrowWord128 w = w `mod` pow2_129
{-# INLINE narrowWord128 #-}

pow2_129 :: Integer
pow2_129 = 1 `shiftL` 129
{-# INLINE pow2_129 #-}

instance Num Word128 where
  (+) (Word128 a) (Word128 b) = Word128 $ narrowWord128 (a + b)
  (-) (Word128 a) (Word128 b) = Word128 $ narrowWord128 (a - b)
  (*) (Word128 a) (Word128 b) = Word128 $ narrowWord128 (a * b)
  abs x                       = x
  signum 0                    = 0
  signum _                    = 1
  fromInteger                 = Word128 . narrowWord128

-- | Timing independent equality comparison
instance Eq Word128 where
  (==) a b = safeAllBS (==0) $ i2osp i 16
    where (Word128 i) = a `xor` b

instance Bounded Word128 where
  minBound = 0
  maxBound = Word128 $ pow2_129 - 1

instance Enum Word128 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word128"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word128"
  toEnum                 = Word128 . toEnum
  fromEnum (Word128 a)   = fromEnum a

instance Bits Word128 where
  (.&.)   (Word128 x) (Word128 y) = Word128 (x .&. y)
  (.|.)   (Word128 x) (Word128 y) = Word128 (x .|. y)
  xor     (Word128 x) (Word128 y) = Word128 (x `xor` y)
  shiftL  (Word128 w) i           = Word128 . narrowWord128 $ shiftL w i
  shiftR  (Word128 w) i           = Word128 . narrowWord128 $ shiftR w i
  rotateL (Word128 w) i           = Word128 . narrowWord128 $ rotateL w i
  rotateR (Word128 w) i           = Word128 . narrowWord128 $ rotateR w i
  bitSize  _                      = 128
  isSigned _                      = False
  popCount                        = popCountDefault
  bit                             = bitDefault
  testBit                         = testBitDefault
