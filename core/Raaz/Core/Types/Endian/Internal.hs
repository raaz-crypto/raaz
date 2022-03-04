{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE TypeFamilies               #-}
module Raaz.Core.Types.Endian.Internal where

import           Control.DeepSeq             ( NFData)
import           Data.Typeable
import           Foreign.Storable            ( Storable )

import           Raaz.Core.Prelude
import           Raaz.Core.Types.Equality


import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )

{-
Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}

-- | Little endian version of the word type @w@
newtype LE w = LE { unLE :: w }
    deriving ( Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, Equality, Ord
             , Bits, Storable, Typeable, NFData
             )

instance Functor LE where
  fmap f = LE . f . unLE

-- | Big endian version of the word type @w@
newtype BE w = BE { unBE :: w }
    deriving ( Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, Equality, Ord
             , Bits, Storable, Typeable, NFData
             )

instance Functor BE where
  fmap f = BE . f . unBE

-- | Convert to the little endian variant.
littleEndian :: w -> LE w
{-# INLINE littleEndian #-}
littleEndian = LE

-- | Convert to the big endian variants.
bigEndian :: w -> BE w
{-# INLINE bigEndian #-}
bigEndian = BE




------------------- Unboxed vector of Endian word types ---------------

instance Unbox w => Unbox (LE w)
instance Unbox w => Unbox (BE w)

------------------- Defining the vector types --------------------------

newtype instance MVector s (LE w) = MV_LE (MVector s w)
newtype instance Vector    (LE w) = V_LE  (Vector w)

newtype instance MVector s (BE w) = MV_BE (MVector s w)
newtype instance Vector    (BE w) = V_BE  (Vector w)

instance Unbox w => GVM.MVector MVector (LE w) where
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
  basicLength          (MV_LE v)        = GVM.basicLength v
  basicUnsafeSlice i n (MV_LE v)        = MV_LE $ GVM.basicUnsafeSlice i n v
  basicOverlaps (MV_LE v1) (MV_LE v2)   = GVM.basicOverlaps v1 v2

  basicUnsafeRead  (MV_LE v) i          = LE <$> GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_LE v) i (LE x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_LE v)                  = GVM.basicClear v
  basicSet   (MV_LE v)         (LE x)   = GVM.basicSet v x

  basicUnsafeNew n                      = MV_LE <$> GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (LE x)     = MV_LE <$> GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_LE v1) (MV_LE v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_LE v)   n         = MV_LE <$> GVM.basicUnsafeGrow v n
  basicInitialize (MV_LE v)           = GVM.basicInitialize v

instance Unbox w => GV.Vector Vector (LE w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_LE v)   = V_LE  <$> GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_LE v)      = MV_LE <$> GV.basicUnsafeThaw v
  basicLength (V_LE v)          = GV.basicLength v
  basicUnsafeSlice i n (V_LE v) = V_LE $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_LE v) i  = LE   <$>  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_LE mv) (V_LE v) = GV.basicUnsafeCopy mv v
  elemseq _ (LE x)                    = GV.elemseq (undefined :: Vector a) x


instance Unbox w => GVM.MVector MVector (BE w) where
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
  basicLength          (MV_BE v)        = GVM.basicLength v
  basicUnsafeSlice i n (MV_BE v)        = MV_BE $ GVM.basicUnsafeSlice i n v
  basicOverlaps (MV_BE v1) (MV_BE v2)   = GVM.basicOverlaps v1 v2

  basicUnsafeRead  (MV_BE v) i          = BE <$> GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_BE v) i (BE x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_BE v)                  = GVM.basicClear v
  basicSet   (MV_BE v)         (BE x)   = GVM.basicSet v x

  basicUnsafeNew n                      = MV_BE <$> GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (BE x)     = MV_BE <$> GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_BE v1) (MV_BE v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_BE v)   n         = MV_BE <$> GVM.basicUnsafeGrow v n
  basicInitialize (MV_BE v)           = GVM.basicInitialize v



instance Unbox w => GV.Vector Vector (BE w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_BE v)   = V_BE  <$> GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_BE v)      = MV_BE <$> GV.basicUnsafeThaw v
  basicLength (V_BE v)          = GV.basicLength v
  basicUnsafeSlice i n (V_BE v) = V_BE $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_BE v) i  = BE   <$>  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_BE mv) (V_BE v) = GV.basicUnsafeCopy mv v
  elemseq _ (BE x)                    = GV.elemseq (undefined :: Vector a) x
