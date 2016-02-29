{-# LANGUAGE CPP                        #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}

module Raaz.Core.Types.Endian
       ( EndianStore(..)
       -- ** Endian explicit word types.
       , LE, BE, littleEndian, bigEndian
       -- ** Helper functions for endian aware storing and loading.
       , storeAt, storeAtIndex
       , loadFrom, loadFromIndex
       ) where

import           Control.DeepSeq             ( NFData)
import           Control.Monad               ( liftM )
import           Data.Bits
import           Data.Monoid
import           Data.Typeable
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Data.Word                   ( Word32, Word64, Word8      )
import           Foreign.Ptr                 ( castPtr      )
import           Foreign.Storable            ( Storable(..) )


import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Types.Equality

-- | This class is the starting point of an endian agnostic interface
-- to basic cryptographic data types. Endianness only matters when we
-- first load the data from the buffer or when we finally write the
-- data out. Any multi-byte type that are meant to be serialised
-- should define and instance of this class. The `load` and `store`
-- should takes care of the appropriate endian conversion.
class Storable w => EndianStore w where

  -- | Store the given value at the locating pointed by the pointer
  store :: Pointer   -- ^ the location.
        -> w           -- ^ value to store
        -> IO ()

  -- | Load the value from the location pointed by the pointer.
  load  :: Pointer -> IO w

instance EndianStore Word8 where
  store = poke . castPtr
  load  = peek . castPtr

{--}
-- | Store the given value as the @n@-th element of the array
-- pointed by the crypto pointer.
storeAtIndex :: EndianStore w
             => Pointer        -- ^ the pointer to the first element of the
                               -- array
             -> Int            -- ^ the index of the array
             -> w              -- ^ the value to store
             -> IO ()
{-# INLINE storeAtIndex #-}
storeAtIndex cptr index w = storeAt cptr offset w
  where offset = toEnum index * byteSize w

-- | Store the given value at an offset from the crypto pointer. The
-- offset is given in type safe units.
storeAt :: ( EndianStore w
           , LengthUnit offset
           )
        => Pointer   -- ^ the pointer
        -> offset      -- ^ the absolute offset in type safe length units.
        -> w           -- ^ value to store
        -> IO ()
{-# INLINE storeAt #-}
storeAt cptr offset = store (Sum offset <.> cptr)

-- | Load the @n@-th value of an array pointed by the crypto pointer.
loadFromIndex :: EndianStore w
              => Pointer -- ^ the pointer to the first element of
                           -- the array
              -> Int       -- ^ the index of the array
              -> IO w
{-# INLINE loadFromIndex #-}
loadFromIndex cptr index = loadP undefined
   where loadP ::  (EndianStore w, Storable w) => w -> IO w
         loadP w = loadFrom cptr offset
           where offset = toEnum index * byteSize w

-- | Load from a given offset. The offset is given in type safe units.
loadFrom :: ( EndianStore w
            , LengthUnit offset
            )
         => Pointer -- ^ the pointer
         -> offset    -- ^ the offset
         -> IO w
{-# INLINE loadFrom #-}
loadFrom cptr offset = load (Sum offset <.> cptr)

--}

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
             , Integral, Num, Real, Eq, Equality, Ord
             , Bits, Storable, Typeable, NFData
             )

-- | Big endian version of the word type @w@
newtype BE w = BE w
    deriving ( Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, Equality, Ord
             , Bits, Storable, Typeable, NFData
             )

-- | Convert to the little endian variant.
littleEndian :: w -> LE w
{-# INLINE littleEndian #-}
littleEndian = LE

-- | Convert to the big endian variants.
bigEndian :: w -> BE w
bigEndian = BE

------------------- Endian store for LE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE32"
  c_loadLE32 :: Pointer -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE32"
  c_storeLE32 :: Pointer -> Word32 -> IO ()

instance EndianStore (LE Word32) where
  load             = fmap LE .  c_loadLE32
  store ptr (LE w) = c_storeLE32 ptr w

------------------- Endian store for BE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE32"
  c_loadBE32 :: Pointer -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE32"
  c_storeBE32 :: Pointer -> Word32 -> IO ()

instance EndianStore (BE Word32) where
  load             = fmap BE .  c_loadBE32
  store ptr (BE w) = c_storeBE32 ptr w


------------------- Endian store for LE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE64"
  c_loadLE64 :: Pointer -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE64"
  c_storeLE64 :: Pointer -> Word64 -> IO ()

instance EndianStore (LE Word64) where
  load             = fmap LE .  c_loadLE64
  store ptr (LE w) = c_storeLE64 ptr w


------------------- Endian store for BE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE64"
  c_loadBE64 :: Pointer -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE64"
  c_storeBE64 :: Pointer -> Word64 -> IO ()

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

#if MIN_VERSION_vector(0,11,0)
  basicInitialize (MV_LE v)           = GVM.basicInitialize v
#endif

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

  basicUnsafeRead  (MV_BE v) i          = BE `liftM` GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_BE v) i (BE x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_BE v)                  = GVM.basicClear v
  basicSet   (MV_BE v)         (BE x)   = GVM.basicSet v x

  basicUnsafeNew n                      = MV_BE `liftM` GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (BE x)     = MV_BE `liftM` GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_BE v1) (MV_BE v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_BE v)   n         = MV_BE `liftM` GVM.basicUnsafeGrow v n

#if MIN_VERSION_vector(0,11,0)
  basicInitialize (MV_BE v)           = GVM.basicInitialize v
#endif



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
  elemseq _ (BE x)                    = GV.elemseq (undefined :: Vector a) x
