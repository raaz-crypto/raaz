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
  complement (Word128 x)          = Word128 $ complement x
  shiftL  (Word128 w) i           = Word128 . narrowWord128 $ shiftL w i
  shiftR  (Word128 w) i           = Word128 . narrowWord128 $ shiftR w i
  rotateL (Word128 w) i           = Word128 . narrowWord128 $ rotateL w i
  rotateR (Word128 w) i           = Word128 . narrowWord128 $ rotateR w i
  bitSize  _                      = 128
  isSigned _                      = False
  popCount                        = popCountDefault
  bit                             = bitDefault
  testBit                         = testBitDefault

-- | 256 Bit Word
newtype Word256 = Word256 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 256 Bits
narrowWord256 :: Integer -> Integer
narrowWord256 w = w `mod` pow2_257
{-# INLINE narrowWord256 #-}

pow2_257 :: Integer
pow2_257 = 1 `shiftL` 257
{-# INLINE pow2_257 #-}

instance Num Word256 where
  (+) (Word256 a) (Word256 b) = Word256 $ narrowWord256 (a + b)
  (-) (Word256 a) (Word256 b) = Word256 $ narrowWord256 (a - b)
  (*) (Word256 a) (Word256 b) = Word256 $ narrowWord256 (a * b)
  abs x                       = x
  signum 0                    = 0
  signum _                    = 1
  fromInteger                 = Word256 . narrowWord256

-- | Timing independent equality comparison
instance Eq Word256 where
  (==) a b = safeAllBS (==0) $ i2osp i 32
    where (Word256 i) = a `xor` b

instance Bounded Word256 where
  minBound = 0
  maxBound = Word256 $ pow2_257 - 1

instance Enum Word256 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word256"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word256"
  toEnum                 = Word256 . toEnum
  fromEnum (Word256 a)   = fromEnum a

instance Bits Word256 where
  (.&.)   (Word256 x) (Word256 y) = Word256 (x .&. y)
  (.|.)   (Word256 x) (Word256 y) = Word256 (x .|. y)
  xor     (Word256 x) (Word256 y) = Word256 (x `xor` y)
  complement (Word256 x)          = Word256 $ complement x
  shiftL  (Word256 w) i           = Word256 . narrowWord256 $ shiftL w i
  shiftR  (Word256 w) i           = Word256 . narrowWord256 $ shiftR w i
  rotateL (Word256 w) i           = Word256 . narrowWord256 $ rotateL w i
  rotateR (Word256 w) i           = Word256 . narrowWord256 $ rotateR w i
  bitSize  _                      = 256
  isSigned _                      = False
  popCount                        = popCountDefault
  bit                             = bitDefault
  testBit                         = testBitDefault

-- | 512 Bit Word
newtype Word512 = Word512 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 512 Bits
narrowWord512 :: Integer -> Integer
narrowWord512 w = w `mod` pow2_513
{-# INLINE narrowWord512 #-}

pow2_513 :: Integer
pow2_513 = 1 `shiftL` 513
{-# INLINE pow2_513 #-}

instance Num Word512 where
  (+) (Word512 a) (Word512 b) = Word512 $ narrowWord512 (a + b)
  (-) (Word512 a) (Word512 b) = Word512 $ narrowWord512 (a - b)
  (*) (Word512 a) (Word512 b) = Word512 $ narrowWord512 (a * b)
  abs x                       = x
  signum 0                    = 0
  signum _                    = 1
  fromInteger                 = Word512 . narrowWord512

-- | Timing independent equality comparison
instance Eq Word512 where
  (==) a b = safeAllBS (==0) $ i2osp i 64
    where (Word512 i) = a `xor` b

instance Bounded Word512 where
  minBound = 0
  maxBound = Word512 $ pow2_513 - 1

instance Enum Word512 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word512"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word512"
  toEnum                 = Word512 . toEnum
  fromEnum (Word512 a)   = fromEnum a

instance Bits Word512 where
  (.&.)   (Word512 x) (Word512 y) = Word512 (x .&. y)
  (.|.)   (Word512 x) (Word512 y) = Word512 (x .|. y)
  xor     (Word512 x) (Word512 y) = Word512 (x `xor` y)
  complement (Word512 x)          = Word512 $ complement x
  shiftL  (Word512 w) i           = Word512 . narrowWord512 $ shiftL w i
  shiftR  (Word512 w) i           = Word512 . narrowWord512 $ shiftR w i
  rotateL (Word512 w) i           = Word512 . narrowWord512 $ rotateL w i
  rotateR (Word512 w) i           = Word512 . narrowWord512 $ rotateR w i
  bitSize  _                      = 512
  isSigned _                      = False
  popCount                        = popCountDefault
  bit                             = bitDefault
  testBit                         = testBitDefault

-- | 1024 Bit Word
newtype Word1024 = Word1024 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 1024 Bits
narrowWord1024 :: Integer -> Integer
narrowWord1024 w = w `mod` pow2_1025
{-# INLINE narrowWord1024 #-}

pow2_1025 :: Integer
pow2_1025 = 1 `shiftL` 1025
{-# INLINE pow2_1025 #-}

instance Num Word1024 where
  (+) (Word1024 a) (Word1024 b) = Word1024 $ narrowWord1024 (a + b)
  (-) (Word1024 a) (Word1024 b) = Word1024 $ narrowWord1024 (a - b)
  (*) (Word1024 a) (Word1024 b) = Word1024 $ narrowWord1024 (a * b)
  abs x                       = x
  signum 0                    = 0
  signum _                    = 1
  fromInteger                 = Word1024 . narrowWord1024

-- | Timing independent equality comparison
instance Eq Word1024 where
  (==) a b = safeAllBS (==0) $ i2osp i 128
    where (Word1024 i) = a `xor` b

instance Bounded Word1024 where
  minBound = 0
  maxBound = Word1024 $ pow2_1025 - 1

instance Enum Word1024 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word1024"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word1024"
  toEnum                 = Word1024 . toEnum
  fromEnum (Word1024 a)   = fromEnum a

instance Bits Word1024 where
  (.&.)   (Word1024 x) (Word1024 y) = Word1024 (x .&. y)
  (.|.)   (Word1024 x) (Word1024 y) = Word1024 (x .|. y)
  xor     (Word1024 x) (Word1024 y) = Word1024 (x `xor` y)
  complement (Word1024 x)           = Word1024 $ complement x
  shiftL  (Word1024 w) i            = Word1024 . narrowWord1024 $ shiftL w i
  shiftR  (Word1024 w) i            = Word1024 . narrowWord1024 $ shiftR w i
  rotateL (Word1024 w) i            = Word1024 . narrowWord1024 $ rotateL w i
  rotateR (Word1024 w) i            = Word1024 . narrowWord1024 $ rotateR w i
  bitSize  _                        = 1024
  isSigned _                        = False
  popCount                          = popCountDefault
  bit                               = bitDefault
  testBit                           = testBitDefault

-- | 2048 Bit Word
newtype Word2048 = Word2048 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 2048 Bits
narrowWord2048 :: Integer -> Integer
narrowWord2048 w = w `mod` pow2_2049
{-# INLINE narrowWord2048 #-}

pow2_2049 :: Integer
pow2_2049 = 1 `shiftL` 2049
{-# INLINE pow2_2049 #-}

instance Num Word2048 where
  (+) (Word2048 a) (Word2048 b) = Word2048 $ narrowWord2048 (a + b)
  (-) (Word2048 a) (Word2048 b) = Word2048 $ narrowWord2048 (a - b)
  (*) (Word2048 a) (Word2048 b) = Word2048 $ narrowWord2048 (a * b)
  abs x                         = x
  signum 0                      = 0
  signum _                      = 1
  fromInteger                   = Word2048 . narrowWord2048

-- | Timing independent equality comparison
instance Eq Word2048 where
  (==) a b = safeAllBS (==0) $ i2osp i 256
    where (Word2048 i) = a `xor` b

instance Bounded Word2048 where
  minBound = 0
  maxBound = Word2048 $ pow2_2049 - 1

instance Enum Word2048 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word2048"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word2048"
  toEnum                 = Word2048 . toEnum
  fromEnum (Word2048 a)   = fromEnum a

instance Bits Word2048 where
  (.&.)   (Word2048 x) (Word2048 y) = Word2048 (x .&. y)
  (.|.)   (Word2048 x) (Word2048 y) = Word2048 (x .|. y)
  xor     (Word2048 x) (Word2048 y) = Word2048 (x `xor` y)
  complement (Word2048 x)           = Word2048 $ complement x
  shiftL  (Word2048 w) i            = Word2048 . narrowWord2048 $ shiftL w i
  shiftR  (Word2048 w) i            = Word2048 . narrowWord2048 $ shiftR w i
  rotateL (Word2048 w) i            = Word2048 . narrowWord2048 $ rotateL w i
  rotateR (Word2048 w) i            = Word2048 . narrowWord2048 $ rotateR w i
  bitSize  _                        = 2048
  isSigned _                        = False
  popCount                          = popCountDefault
  bit                               = bitDefault
  testBit                           = testBitDefault

-- | 4096 Bit Word
newtype Word4096 = Word4096 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 4096 Bits
narrowWord4096 :: Integer -> Integer
narrowWord4096 w = w `mod` pow2_4097
{-# INLINE narrowWord4096 #-}

pow2_4097 :: Integer
pow2_4097 = 1 `shiftL` 4097
{-# INLINE pow2_4097 #-}

instance Num Word4096 where
  (+) (Word4096 a) (Word4096 b) = Word4096 $ narrowWord4096 (a + b)
  (-) (Word4096 a) (Word4096 b) = Word4096 $ narrowWord4096 (a - b)
  (*) (Word4096 a) (Word4096 b) = Word4096 $ narrowWord4096 (a * b)
  abs x                         = x
  signum 0                      = 0
  signum _                      = 1
  fromInteger                   = Word4096 . narrowWord4096

-- | Timing independent equality comparison
instance Eq Word4096 where
  (==) a b = safeAllBS (==0) $ i2osp i 512
    where (Word4096 i) = a `xor` b

instance Bounded Word4096 where
  minBound = 0
  maxBound = Word4096 $ pow2_4097 - 1

instance Enum Word4096 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: Word4096"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: Word4096"
  toEnum                 = Word4096 . toEnum
  fromEnum (Word4096 a)   = fromEnum a

instance Bits Word4096 where
  (.&.)   (Word4096 x) (Word4096 y) = Word4096 (x .&. y)
  (.|.)   (Word4096 x) (Word4096 y) = Word4096 (x .|. y)
  xor     (Word4096 x) (Word4096 y) = Word4096 (x `xor` y)
  complement (Word4096 x)           = Word4096 $ complement x
  shiftL  (Word4096 w) i            = Word4096 . narrowWord4096 $ shiftL w i
  shiftR  (Word4096 w) i            = Word4096 . narrowWord4096 $ shiftR w i
  rotateL (Word4096 w) i            = Word4096 . narrowWord4096 $ rotateL w i
  rotateR (Word4096 w) i            = Word4096 . narrowWord4096 $ rotateR w i
  bitSize  _                        = 4096
  isSigned _                        = False
  popCount                          = popCountDefault
  bit                               = bitDefault
  testBit                           = testBitDefault

-- | 8192 Bit Word
newtype Word8192 = Word8192 Integer
                  deriving (Integral, Show, Ord, Real, Modular)

-- | Reduced Int to lower order 8192 Bits
narrowWord8192 :: Integer -> Integer
narrowWord8192 w = w `mod` pow2_8193
{-# INLINE narrowWord8192 #-}

pow2_8193 :: Integer
pow2_8193 = 1 `shiftL` 8193
{-# INLINE pow2_8193 #-}

instance Num Word8192 where
  (+) (Word8192 a) (Word8192 b) = Word8192 $ narrowWord8192 (a + b)
  (-) (Word8192 a) (Word8192 b) = Word8192 $ narrowWord8192 (a - b)
  (*) (Word8192 a) (Word8192 b) = Word8192 $ narrowWord8192 (a * b)
  abs x                         = x
  signum 0                      = 0
  signum _                      = 1
  fromInteger                   = Word8192 . narrowWord8192

-- | Timing independent equality comparison
instance Eq Word8192 where
  (==) a b = safeAllBS (==0) $ i2osp i 1024
    where (Word8192 i) = a `xor` b

instance Bounded Word8192 where
  minBound = 0
  maxBound = Word8192 $ pow2_8193 - 1

instance Enum Word8192 where
  succ x | x /= maxBound  = x + 1
         | otherwise      = error "succ: Word8192"
  pred x | x /= minBound  = x - 1
         | otherwise      = error "pred: Word8192"
  toEnum                  = Word8192 . toEnum
  fromEnum (Word8192 a)   = fromEnum a

instance Bits Word8192 where
  (.&.)   (Word8192 x) (Word8192 y) = Word8192 (x .&. y)
  (.|.)   (Word8192 x) (Word8192 y) = Word8192 (x .|. y)
  xor     (Word8192 x) (Word8192 y) = Word8192 (x `xor` y)
  complement (Word8192 x)           = Word8192 $ complement x
  shiftL  (Word8192 w) i            = Word8192 . narrowWord8192 $ shiftL w i
  shiftR  (Word8192 w) i            = Word8192 . narrowWord8192 $ shiftR w i
  rotateL (Word8192 w) i            = Word8192 . narrowWord8192 $ rotateL w i
  rotateR (Word8192 w) i            = Word8192 . narrowWord8192 $ rotateR w i
  bitSize  _                        = 8192
  isSigned _                        = False
  popCount                          = popCountDefault
  bit                               = bitDefault
  testBit                           = testBitDefault
