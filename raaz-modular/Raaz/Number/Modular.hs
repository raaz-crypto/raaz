{- |

This module implements Modular arithmetic on Integers.

-}
{-# LANGUAGE CPP           #-}
{-# LANGUAGE BangPatterns  #-}
module Raaz.Number.Modular
    ( Modular(..)
    , powModuloSlow
    ) where

import Data.Bits
import Raaz.Number.Util

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
#endif

-- | Captures modular arithmetic for a given type. It is useful to
-- just derive this for newtype wrappers over Integers as we dont want
-- to expose the constructors of these newtypes.
class Modular a where
  -- | Computes @base ^ exponent mod Modulo@ using the fastest
  -- algorithm available. This may be subject to side channel attacks
  -- and should not be used where side channel attacks on this
  -- function can compromise the security of cryptographic protocols.
  powModulo :: a -- ^ Base
            -> a -- ^ Exponent
            -> a -- ^ Modulo
            -> a -- ^ result

  -- | Safe version of powModulo which is resistant to side channel
  -- attacks. It is required that Modulo is odd otherwise the unsafe
  -- modular exponentiation is used.
  powModuloSafe :: a -- ^ Base
                -> a -- ^ Exponent
                -> a -- ^ Modulo
                -> a -- ^ result

instance Modular Integer where
#if MIN_VERSION_integer_gmp(0,5,1)
  powModulo = powModInteger
#else
  powModulo = powModuloSlow
#endif

#if MIN_VERSION_integer_gmp(0,5,1)
  powModuloSafe b e m | odd m      = powModSecInteger b e m
                      | otherwise  = powModInteger b e m
#else
  powModuloSafe = powModuloSlow
#endif

-- | Modular exponentiation @x^n mod m@ using binary exponentiation.
powModuloSlow :: Integer -> Integer -> Integer -> Integer
powModuloSlow x n m = go x nbits 1
 where
  nbits             = fromEnum $ numberOfBits n
  go _   0 !result  = result `mod` m
  go !b !nb !result = go b' (nb-1) result'
   where
    !b'      = (b * b) `mod` m
    !result' | testBit n (nbits - nb) = result * b
             | otherwise              = result
