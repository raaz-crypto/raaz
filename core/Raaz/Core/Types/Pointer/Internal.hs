{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
--
-- Module      : Raaz.Core.Types.Pointer.Internal
-- Copyright   : (c) Piyush P Kurur, 2022
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental

module Raaz.Core.Types.Pointer.Internal where


import           GHC.TypeLits
import           Foreign.Storable      ( Storable )
import           Foreign.Ptr           ( Ptr )

import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM

import Raaz.Core.Prelude
import Raaz.Core.Types.Equality

------------------ Bytes -----------------------------------------

-- | Type safe lengths/offsets in units of bytes.
newtype BYTES a  = BYTES a
        deriving ( Show, Eq, Equality, Ord, Enum, Integral
                 , Real, Num, Storable, Bounded, Bits
                 )

instance Functor BYTES where
   fmap f (BYTES x) = BYTES (f x)

instance Num a => Semigroup (BYTES a) where
  (<>) = (+)

instance Num a => Monoid (BYTES a) where
  mempty  = 0
  mappend = (<>)


------------------------ Alignment --------------------------------

-- | Types to measure alignment in units of bytes.
newtype Alignment = Alignment { unAlignment :: Int }
        deriving ( Show, Eq, Ord, Enum)

instance Semigroup Alignment where
  (<>) a b = Alignment $ lcm (unAlignment a) (unAlignment b)

instance Monoid Alignment where
  mempty  = Alignment 1
  mappend = (<>)


-------------------------------------------------------------------

-- | The type @AlignedPtr n@ that captures pointers that are aligned
-- to @n@ byte boundary.
newtype AlignedPtr (n :: Nat) a = AlignedPtr { forgetAlignment :: Ptr a}


--------------------------

instance Unbox w => Unbox (BYTES w)
newtype instance MVector s (BYTES w) = MV_BYTES (MVector s w)
newtype instance Vector    (BYTES w) = V_BYTES  (Vector w)

instance Unbox w => GVM.MVector MVector (BYTES w) where
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
  basicLength          (MV_BYTES v)           = GVM.basicLength v
  basicUnsafeSlice i n (MV_BYTES v)           = MV_BYTES $ GVM.basicUnsafeSlice i n v
  basicOverlaps (MV_BYTES v1) (MV_BYTES v2)   = GVM.basicOverlaps v1 v2

  basicUnsafeRead  (MV_BYTES v) i             = BYTES <$> GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_BYTES v) i (BYTES x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_BYTES v)                     = GVM.basicClear v
  basicSet   (MV_BYTES v)         (BYTES x)   = GVM.basicSet v x

  basicUnsafeNew n                            = MV_BYTES <$> GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (BYTES x)        = MV_BYTES <$> GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_BYTES v1) (MV_BYTES v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_BYTES v)   n            = MV_BYTES <$> GVM.basicUnsafeGrow v n
  basicInitialize (MV_BYTES v)                = GVM.basicInitialize v



instance Unbox w => GV.Vector Vector (BYTES w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_BYTES v)            = V_BYTES  <$> GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_BYTES v)               = MV_BYTES <$> GV.basicUnsafeThaw v
  basicLength (V_BYTES v)                   = GV.basicLength v
  basicUnsafeSlice i n (V_BYTES v)          = V_BYTES $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_BYTES v) i           = BYTES   <$>  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_BYTES mv) (V_BYTES v) = GV.basicUnsafeCopy mv v
  elemseq _ (BYTES x)                       = GV.elemseq (undefined :: Vector a) x
