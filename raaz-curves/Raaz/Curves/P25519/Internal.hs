{- |

Type for the prime P25519.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.P25519.Internal
      ( P25519(..)
      ) where

import Data.Bits
import Data.Typeable
import Foreign.Storable

import Raaz.Number.Internals
import Raaz.Number

-- | Modulo Prime 2^255 - 19
newtype P25519 = P25519 Word256
                  deriving (Integral, Show, Ord, Real, Modular, Typeable, Eq, Storable)

-- | Reduced Word256 to module prime p25519
narrowP25519 :: Word256 -> Word256
narrowP25519 w = w `mod` p25519
{-# INLINE narrowP25519 #-}

p25519 :: Word256
p25519 = (1 `shiftL` 255) - 19
{-# INLINE p25519 #-}

instance Num P25519 where
  (+) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a + b)
  (-) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a - b)
  (*) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a * b)
  abs x                     = x
  signum 0                  = 0
  signum _                  = 1
  fromInteger               = P25519 . narrowP25519 . narrowToWord256

instance Bounded P25519 where
  minBound = 0
  maxBound = P25519 $ p25519 - 1

instance Enum P25519 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: P25519"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: P25519"
  toEnum                 = P25519 . toEnum
  fromEnum (P25519 a)    = fromEnum a
