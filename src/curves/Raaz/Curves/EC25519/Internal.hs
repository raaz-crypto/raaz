{- |

This module gives the reference implementation of the DH functions
over Curve25519. There is a faster recommended implementation available.
So you /should not/ be using this code in production unless you know
what you are doing.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.EC25519.Internal
      ( P25519(..)
      , PointProj(..)
      , Secret25519(..)
      , PublicToken25519(..)
      , SharedSecret25519(..)
      , generateSecretEC25519
      , publicToken
      , sharedSecret
      , curve25519P
      , curve25519Gx
      , integerToP25519
      , p25519toInteger
      , getRandomP25519
      , getRandomForSecret
      , sizeOf
      ) where

import Control.Applicative ( (<$>), (<*>) )
import Data.Bits
import Data.Monoid
import Data.Typeable
import Data.Word
import Foreign.Ptr         ( castPtr      )
import Foreign.Storable    ( peek, Storable(..) )

import Raaz.Core.DH
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Random
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe
import Raaz.System.Random

-- | Affine representation of points on the curve
data PointAffine w = PointAffine { ax :: w } deriving Show

-- | Projective representation of points on the curve
data PointProj w = PointProj { px :: w, pz :: w } deriving Show

instance Eq w => Eq (PointAffine w) where
  (PointAffine x) == (PointAffine x') = x == x'

instance Eq w => Eq (PointProj w) where
  (PointProj x z) == (PointProj x' z') = x == x' && z == z'

------------------------------ EC25519 Constants ------------------------------
-- Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
-- for EC25519 A = 486662, C = A/4, w = P25519,
-- prime p = 2^255 - 19, basepoint Gx = 9

-- | The prime number (2^255 - 19)
curve25519P :: Integer
curve25519P  = 57896044618658097711785492504343953926634992332820282019728792003956564819949
{-# INLINE curve25519P #-}

-- | The constant C for the curve EC25519 (equals A/4)
curve25519C :: Integer
curve25519C  = 121665
{-# INLINE curve25519C #-}

-- | The x-coordinate of the basepoint
curve25519Gx :: Integer
curve25519Gx  = 9
{-# INLINE curve25519Gx #-}

-- | Representation of the point at infinity
pInfinity :: PointProj Integer
pInfinity = PointProj 1 0
{-# INLINE pInfinity #-}

-- | Data type for numbers in the field - Modulo Prime curve25519P (2^255 - 19)
-- in Little-endian representation (same as the recommended implementation)
data P25519 = P25519 {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64) deriving (Show, Typeable)

-- | Secret
newtype Secret25519 = Secret25519 P25519 deriving (Eq, Show)

-- | Public Token
newtype PublicToken25519 = PublicToken25519 P25519 deriving (Eq, Show)

-- | Shared Secret
newtype SharedSecret25519 = SharedSecret25519 P25519 deriving (Eq, Show)

-------------------- Instances for the type P25519 ----------------------------
-- | Timing independent equality testing.
instance Eq P25519 where
  (==) (P25519 g0 g1 g2 g3) (P25519 h0 h1 h2 h3) = xor g0 h0
                                               .|. xor g1 h1
                                               .|. xor g2 h2
                                               .|. xor g3 h3
                                                == 0
-- | Storable class instance
instance Storable P25519 where
  sizeOf    _ = 4 * sizeOf (undefined :: (LE Word64))
  alignment _ = alignment  (undefined :: (LE Word64))
  peek ptr = runParser cptr parseP25519
    where parseP25519 = P25519 <$> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (P25519 h0 h1 h2 h3) =  runWrite cptr writeP25519
    where writeP25519 = writeStorable h0
                     <> writeStorable h1
                     <> writeStorable h2
                     <> writeStorable h3
          cptr = castPtr ptr

-- | EndianStore class instance
instance EndianStore P25519 where
  load cptr = runParser cptr parseP25519
    where parseP25519 = P25519 <$> parse
                               <*> parse
                               <*> parse
                               <*> parse

  store cptr (P25519 h0 h1 h2 h3) =  runWrite cptr writeP25519
    where writeP25519 = write h0
                     <> write h1
                     <> write h2
                     <> write h3

-- | Diffie-Hellman class' instance
instance DH P25519 where
  type Secret P25519       = Secret25519
  type PublicToken P25519  = PublicToken25519
  type SharedSecret P25519 = SharedSecret25519

  publicToken _ (Secret25519 secret) = PublicToken25519 pubToken
    where
      iSecret      = p25519toInteger secret
      iPublicPoint = pMult iSecret (PointProj curve25519Gx 1)
      iPublicToken = ax (affinify iPublicPoint)
      pubToken     = integerToP25519 iPublicToken

  sharedSecret _ (Secret25519 secret) (PublicToken25519 pubToken) = SharedSecret25519 sharedSec
    where
      iSecret       = p25519toInteger secret
      iPubToken     = p25519toInteger pubToken
      iSharedPoint  = pMult iSecret (PointProj iPubToken 1)
      iSharedSecret = ax (affinify iSharedPoint)
      sharedSec     = integerToP25519 iSharedSecret

-- | Reduce integer to modulo prime curve25519P
narrowP25519 :: Integer -> Integer
narrowP25519 w = w `mod` curve25519P
{-# INLINE narrowP25519 #-}

-- | Convert a P25519 number to Integer
p25519toInteger :: P25519 -> Integer
p25519toInteger (P25519 a0 a1 a2 a3) = i
  where i0 = toInteger a0
        i1 = toInteger a1
        i2 = toInteger a2
        i3 = toInteger a3
        i  = (i3 `shiftL` 192) + (i2 `shiftL` 128) + (i1 `shiftL` 64) + i0

-- | Convert an integer to P25519
integerToP25519 :: Integer -> P25519
integerToP25519 i = P25519 p0 p1 p2 p3
  where x  = narrowP25519 i
        p0 = fromInteger $ x .&. ((1 `shiftL` 64) - 1)
        p1 = fromInteger $ (x `shiftR` 64) .&. ((1 `shiftL` 64) - 1)
        p2 = fromInteger $ (x `shiftR` 128) .&. ((1 `shiftL` 64) - 1)
        p3 = fromInteger $ (x `shiftR` 192) .&. ((1 `shiftL` 64) - 1)

-- | Point doubling - takes a point in projective form as input
pDouble :: (PointProj Integer) -> (PointProj Integer)
pDouble (PointProj _ 0)   = pInfinity
pDouble (PointProj x1 z1) = PointProj x2 z2
  where
    m  = (x1 + z1) * (x1 + z1)
    n  = (x1 - z1) * (x1 - z1)
    r  = m - n
    s  = m + (curve25519C * r)
    x2 = narrowP25519 $ m * n
    z2 = narrowP25519 $ r * s

-- | Point addition - takes basepoint & 2 points in projective form as input
-- The basepoint is either the basepoint of curve (in case of public token
-- computation) or the public token of the other party (in case of shared
-- secret computation)
pAdd :: (PointProj Integer) -> (PointProj Integer) -> (PointProj Integer) -> (PointProj Integer)
pAdd _ (PointProj _ 0) (PointProj _ 0) = pInfinity
pAdd _ (PointProj _ 0) pt              = pt
pAdd _ pt              (PointProj _ 0) = pt
pAdd basepoint point1@(PointProj x1 z1) point2@(PointProj x2 z2)
  | (point1 == point2) = pDouble point1
  | e == 0             = pDouble point1
  | otherwise          = PointProj x3 z3
  where
    m  = (x1 + z1) * (x2 - z2)
    n  = (x1 - z1) * (x2 + z2)
    e  = (m - n) * (m - n)
    x3 = narrowP25519 $ (m + n) * (m + n)
    z3 = narrowP25519 $ e * (px basepoint)

-- | Point multiplication - takes a multiplier & basepoint in projective form
-- as input. The basepoint is either the basepoint of curve (in case of public
-- token computation) or the public token of the other party (in case of shared
-- secret computation)
pMult :: Integer -> (PointProj Integer) -> (PointProj Integer)
pMult k basepoint = montgom nbits pInfinity basepoint
  where
    nbits = numberOfBits k 0
    numberOfBits n count
     | n == 0    = count
     | otherwise = numberOfBits (n `shiftR` 1) (count+1)
    montgom 0 r0 _ = r0
    montgom bitnum r0 r1
     | testBit k (bitnum - 1) = let r1r1 = pDouble r1
                              in montgom (bitnum-1) r0r1 r1r1
     | otherwise = let r0r0 = pDouble r0
                   in montgom (bitnum-1) r0r0 r0r1
     where r0r1 = pAdd basepoint r0 r1

-- Converts a point in projective form to affine form
affinify :: (PointProj Integer) -> (PointAffine Integer)
affinify (PointProj x z) = (PointAffine x1)
  where
    zinv  = powModuloSlowSafe z (curve25519P - 2)
    x1    = narrowP25519 $ x * zinv
    powModuloSlowSafe g k = operate nbits 1 g
      where
        nbits = numberOfBits k 0
        numberOfBits n count
         | n == 0    = count
         | otherwise = numberOfBits (n `shiftR` 1) (count+1)
        operate 0 r0 _ = r0
        operate bitnum r0 r1
         | testBit k (bitnum-1) = let r1r1 = narrowP25519 $ r1 * r1
                                  in operate (bitnum-1) r0r1 r1r1
         | otherwise = let r0r0 = narrowP25519 $ r0 * r0
                       in operate (bitnum-1) r0r0 r0r1
         where r0r1 = narrowP25519 $ r0 * r1

-- | Generate secret (P25519) from a random P25519 number as specified in
-- DJB's paper
getSecretFromRandom :: P25519 -> P25519
getSecretFromRandom random = secret
  where
    iRandom = p25519toInteger random
    temp1 = (((1 `shiftL` 248) - 1) `shiftL` 8) + 248
    -- temp1: (256 bit number with 248 1's followed by 248)
    temp2 = iRandom .&. temp1
    -- (Rightmost-byte `AND` with 248)
    temp3 = (127 `shiftL` 248) .|. ((1 `shiftL` 248) - 1)
    -- temp3: (256 bit number with 127 followed by 248 1's)
    temp4 = temp2 .&. temp3
    -- (Leftmost-byte `AND` with 127)
    temp5 = 64 `shiftL` 248
    -- temp5: (256 bit number with 64 followed by 248 1's)
    iSecret = temp4 .|. temp5
    -- (Leftmost-byte `OR` with 64)
    secret = integerToP25519 iSecret

-- | Given a random number, generates the secret
generateSecretEC25519 :: P25519 -> Secret P25519
generateSecretEC25519 random = Secret25519 secret
  where secret = getSecretFromRandom random

-- | Generates a random P25519 (`mod` curve25519P) number using the system's
-- PRG(eg: /dev/urandom/)
getRandomP25519 :: IO P25519
getRandomP25519 = do
  stdPRG <- ((newPRG undefined) :: (IO SystemPRG))
  p <- fromPRG stdPRG
  return $ integerToP25519 (narrowP25519 (p25519toInteger p))

-- | Generates a random 32-byte number (not `mod` curve25519P)
getRandomForSecret :: IO P25519
getRandomForSecret = do
  stdPRG <- ((newPRG undefined) :: (IO SystemPRG))
  fromPRG stdPRG
