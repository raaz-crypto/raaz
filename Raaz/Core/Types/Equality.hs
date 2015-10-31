{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts      #-}
module Raaz.Core.Types.Equality
       ( Result
       , Equality, (===)
       , oftenCorrectEqVector, eqVector
       ) where

import           Control.Monad               ( liftM )
import           Data.Bits
import           Data.Monoid
import qualified Data.Vector.Generic         as G
import qualified Data.Vector.Generic.Mutable as GM
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Data.Word

-- | The result of the comparison. The monoid operation accumulates
-- the results of multiple comparisons into one. If any of the
-- equality comparisons fail the resulting comparison fails.
newtype Result =  Result { unResult :: Word } deriving Eq

instance Monoid Result where
  mempty      = Result 0
  mappend a b = Result (unResult a .|. unResult b)



newtype instance MVector s Result = MV_Result (MVector s Word)
newtype instance Vector    Result = V_Result  (Vector Word)

instance Unbox Result

instance GM.MVector MVector Result where
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicOverlaps #-}
  {-# INLINE basicUnsafeNew #-}
  {-# INLINE basicUnsafeReplicate #-}
  {-# INLINE basicUnsafeRead #-}
  {-# INLINE basicUnsafeWrite #-}
  {-# INLINE basicClear #-}
  {-# INLINE basicSet #-}
  {-# INLINE basicUnsafeCopy #-}
  {-# INLINE basicUnsafeGrow #-}
  basicLength          (MV_Result v)            = GM.basicLength v
  basicUnsafeSlice i n (MV_Result v)            = MV_Result $ GM.basicUnsafeSlice i n v
  basicOverlaps (MV_Result v1) (MV_Result v2)   = GM.basicOverlaps v1 v2

  basicUnsafeRead  (MV_Result v) i              = Result `liftM` GM.basicUnsafeRead v i
  basicUnsafeWrite (MV_Result v) i (Result x)   = GM.basicUnsafeWrite v i x

  basicClear (MV_Result v)                      = GM.basicClear v
  basicSet   (MV_Result v)         (Result x)   = GM.basicSet v x

  basicUnsafeNew n                              = MV_Result `liftM` GM.basicUnsafeNew n
  basicUnsafeReplicate n     (Result x)         = MV_Result `liftM` GM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_Result v1) (MV_Result v2) = GM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_Result v)   n             = MV_Result `liftM` GM.basicUnsafeGrow v n



instance G.Vector Vector Result where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_Result v)             = V_Result  `liftM` G.basicUnsafeFreeze v
  basicUnsafeThaw (V_Result v)                = MV_Result `liftM` G.basicUnsafeThaw v
  basicLength (V_Result v)                    = G.basicLength v
  basicUnsafeSlice i n (V_Result v)           = V_Result $ G.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_Result v) i            = Result   `liftM`  G.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_Result mv) (V_Result v) = G.basicUnsafeCopy mv v
  elemseq _ (Result x)                        = G.elemseq (undefined :: Vector a) x



-- | In a cryptographic setting, naive equality checking
-- dangerous. This class is the timing safe way of doing equality
-- checking. The recommended method of defining equality checking for
-- cryptographically sensitive data is as follows.
--
-- 1. Define an instance of `Equality`.
-- 2. Make use of the above instance to define `Eq` instance as follows.
--
-- instance Eq SomeType where
--      (==) a b = a === b
--
class Equality a where
  eq :: a -> a -> Result

(===) :: Equality a => a -> a -> Bool
(===) a b = unResult (eq a b) == 0

instance Equality Word where
  eq a b = Result $ a `xor` b

instance Equality Word8 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2

instance Equality Word16 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2

instance Equality Word32 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2


#include "MachDeps.h"
instance Equality Word64 where
-- It assumes that Word size is atleast 32 Bits
#if WORD_SIZE_IN_BITS < 64
  eq w1 w2 = eq w11 w21 `mappend` eq w12 w22
    where
      w11 :: Word
      w12 :: Word
      w21 :: Word
      w22 :: Word
      w11 = fromIntegral $ w1 `shiftR` 32
      w12 = fromIntegral $ w1
      w21 = fromIntegral $ w2 `shiftR` 32
      w22 = fromIntegral $ w2
#else
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2
#endif


-- | Timing independent equality checks for vector of values. /Do not/
-- use this to check the equality of two general vectors in a timing
-- independent manner (use `eqVector` instead) because:
--
-- 1. They do not work for vectors of unequal lengths,
--
-- 2. They do not work for empty vectors.
--
-- The use case is for defining equality of data types which have
-- fixed size vector quantities in it. Like for example
--
-- > import Data.Vector.Unboxed
-- > newtype Sha1 = Sha1 (Vector (BE Word32))
-- >
-- > instance Eq Sha1 where
-- >    (==) (Sha1 g) (Sha1 h) = oftenCorrectEqVector g h
-- >
--


oftenCorrectEqVector :: (G.Vector v a, Equality a, G.Vector v Result) => v a -> v a -> Bool
oftenCorrectEqVector v1 v2 =  G.foldl1' mappend (G.zipWith eq v1 v2) == Result 0

-- | Timing independent equality checks for vectors. If you know that
-- the vectors are not empty and of equal length, you may use the
-- slightly faster `oftenCorrectEqVector`
eqVector :: (G.Vector v a, Equality a, G.Vector v Result) => v a -> v a -> Bool
eqVector v1 v2 | G.length v1 == G.length v2 = G.foldl' mappend (Result 0) (G.zipWith eq v1 v2) == Result 0
               | otherwise                  = False
