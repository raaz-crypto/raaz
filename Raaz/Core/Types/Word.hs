{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}


-- | This module provide versions of the word type, i.e. types exposed
-- from "Data.Word", with their endianness explicitly specified: the
-- type @LE w@ (@BE w@) is @w@ with little-endian (respectively
-- big-endian) encoding.  These types inherit their parent type's
-- `Num` instance (besides `Ord`, `Eq` etc). The advantage is the
-- following uniformity in their usage in Haskell code:
--
-- 1. For any word type @w@, numeric constants are represented in
--    their Haskell notation (which is big endian). For example, 0xF0
--    represents the number 240 whether the LE or the BE variant.
--
-- 2. The normal arithmetic work on them.
--
-- 3. They have the same printed form except for the constructor
--    sticking around.
--
-- Therefore, as far as Haskell programmers are concerned, the endian
-- explicit version of the word type @w@ behave pretty much the same
-- way as @w@. However, we provide of `EndianStore` instances to the
-- endian explicit versions of `Word32` and `Word64` therefore making
-- them suitable for serialisation without endian confusion.
--
-- Complicated endian sensitive data types like hashes are built out
-- of these basic types. For example SHA1 is defined as
--
-- > data SHA1 = SHA1 (BE Word32) (BE Word32) (BE Word32) (BE Word32) (BE Word32)
--
-- Then the `EndianStore` instance boils down to storing the words in
-- correct order.

module Raaz.Core.Types.Word
       ( LE (..), BE(..)
       ) where

import Control.Monad              ( liftM )
import Data.Bits
import Data.Typeable
import Data.Vector.Unboxed        (MVector(..), Vector, Unbox)
import qualified Data.Vector.Generic as GV
import qualified Data.Vector.Generic.Mutable as GVM
import Data.Word
import Foreign.Storable

import Raaz.Core.Classes

{-

Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}

-- | Little endian version of the word type @w@
newtype LE w = LE w
    deriving ( Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, EqWord, Ord
             , Bits, Storable, Typeable
             )


-- | Big endian version of the word type @w@
newtype BE w = BE w
    deriving ( Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, EqWord, Ord
             , Bits, Storable, Typeable
             )

instance HasName w => HasName (LE w) where
  getName (LE w) = "LE " ++ getName w

instance HasName w => HasName (BE w) where
  getName (BE w) = "BE " ++ getName w

--  We should be able to coerce from a word type to its endian
--  explicit form but not otherwise.
instance CryptoCoerce w (LE w) where
  cryptoCoerce = LE

instance CryptoCoerce w (BE w) where
  cryptoCoerce = BE

------------------- Endian store for LE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE32"
  c_loadLE32 :: CryptoPtr -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE32"
  c_storeLE32 :: CryptoPtr -> Word32 -> IO ()

instance EndianStore (LE Word32) where
  load             = fmap LE .  c_loadLE32
  store ptr (LE w) = c_storeLE32 ptr w

------------------- Endian store for BE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE32"
  c_loadBE32 :: CryptoPtr -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE32"
  c_storeBE32 :: CryptoPtr -> Word32 -> IO ()

instance EndianStore (BE Word32) where
  load             = fmap BE .  c_loadBE32
  store ptr (BE w) = c_storeBE32 ptr w


------------------- Endian store for LE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE64"
  c_loadLE64 :: CryptoPtr -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE64"
  c_storeLE64 :: CryptoPtr -> Word64 -> IO ()

instance EndianStore (LE Word64) where
  load             = fmap LE .  c_loadLE64
  store ptr (LE w) = c_storeLE64 ptr w

------------------- Endian store for BE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE64"
  c_loadBE64 :: CryptoPtr -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE64"
  c_storeBE64 :: CryptoPtr -> Word64 -> IO ()

instance EndianStore (BE Word64) where
  load             = fmap BE .  c_loadBE64
  store ptr (BE w) = c_storeBE64 ptr w


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

  basicUnsafeRead  (MV_LE v) i          = LE `liftM` GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_LE v) i (LE x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_LE v)                  = GVM.basicClear v
  basicSet   (MV_LE v)         (LE x)   = GVM.basicSet v x

  basicUnsafeNew n                      = MV_LE `liftM` GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (LE x)     = MV_LE `liftM` GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_LE v1) (MV_LE v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_LE v)   n         = MV_LE `liftM` GVM.basicUnsafeGrow v n


instance Unbox w => GV.Vector Vector (LE w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_LE v)   = V_LE  `liftM` GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_LE v)      = MV_LE `liftM` GV.basicUnsafeThaw v
  basicLength (V_LE v)          = GV.basicLength v
  basicUnsafeSlice i n (V_LE v) = V_LE $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_LE v) i  = LE   `liftM`  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_LE mv) (V_LE v) = GV.basicUnsafeCopy mv v
  elemseq _ (LE x) y                  = GV.elemseq (undefined :: Vector a) x y


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

  basicUnsafeRead  (MV_BE v) i          = BE `liftM` GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_BE v) i (BE x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_BE v)                  = GVM.basicClear v
  basicSet   (MV_BE v)         (BE x)   = GVM.basicSet v x

  basicUnsafeNew n                      = MV_BE `liftM` GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (BE x)     = MV_BE `liftM` GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_BE v1) (MV_BE v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_BE v)   n         = MV_BE `liftM` GVM.basicUnsafeGrow v n


instance Unbox w => GV.Vector Vector (BE w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_BE v)   = V_BE  `liftM` GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_BE v)      = MV_BE `liftM` GV.basicUnsafeThaw v
  basicLength (V_BE v)          = GV.basicLength v
  basicUnsafeSlice i n (V_BE v) = V_BE $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_BE v) i  = BE   `liftM`  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_BE mv) (V_BE v) = GV.basicUnsafeCopy mv v
  elemseq _ (BE x) y                  = GV.elemseq (undefined :: Vector a) x y
