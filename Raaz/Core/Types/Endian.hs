{-# LANGUAGE CPP                        #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}

module Raaz.Core.Types.Endian
       ( -- * Endianess aware types.
         -- $endianness$
         EndianStore(..)
       -- ** Endian explicit word types.
       , LE, BE, littleEndian, bigEndian
       -- ** Helper functions for endian aware storing and loading.
       , storeAt, storeAtIndex
       , loadFrom, loadFromIndex
       ) where

import           Control.Applicative
import           Control.DeepSeq             ( NFData)
import           Control.Monad               ( liftM )
import           Data.Bits
import           Data.Typeable
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Data.Word                   ( Word32, Word64, Word8      )
import           Foreign.Ptr                 ( castPtr, Ptr )
import           Foreign.Storable            ( Storable(..) )


import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Types.Equality
import           Raaz.Core.Types.Copying


-- $endianness$
--
-- Cryptographic primitives often consider their input as an array of
-- words of a particular endianness. Endianness is only relevant when
-- the data is being read or written to. It makes sense therefore to
-- keep track of the endianness in the type and perform necessary
-- transformations depending on the endianness of the
-- machine. Such types are captured by the type class `EndianStore`. They
-- support the `load` and `store` combinators that automatically compensates
-- for the endianness of the machine.
--
-- This libraray exposes endian aware variants of `Word32` and
-- `Word64` here and expect other cryptographic types to use such
-- endian explicit types in their definition.


-- | This class is the starting point of an endian agnostic interface
-- to basic cryptographic data types. Endianness only matters when we
-- first load the data from the buffer or when we finally write the
-- data out. Any multi-byte type that are meant to be serialised
-- should define and instance of this class. The `load`, `store`,
-- `copy` and  should takes care of the appropriate endian
-- conversion.
--
class Storable w => EndianStore w where

  -- | Store the given value at the locating pointed by the pointer
  store :: Pointer   -- ^ the location.
        -> w         -- ^ value to store
        -> IO ()

  -- | Load the value from the location pointed by the pointer.
  load  :: Pointer -> IO w

  -- | Copy values of this type for a pointer to another. This function
  -- should take care of performing appropriate endian conversion. For
  -- example, if the type `w` was LE Word32, irrespective of what the
  -- underlying architecture is, if the source pointer contains data
  -- `0x01 0x00 0x00 0x00', it should store in the destination pointer
  -- the value `0x01 :: Word32`. In other words, the following law
  -- should essentially be true (the code fails because it is not able
  -- to infer the t.
  --
  -- >
  -- > copy u (Dest dptr) (Src sptr) = loadIt u >>= poke dptr
  -- >      where loadIt :: EndianStore u => u -> u
  --              loadIt x = load
  --
  -- However, we /do not/ have a default definition for this function
  -- precisely because we want the date to be transfered directly from
  -- the source to destination without the pure value being read into
  -- the Haskell heap. Values in heap cannot be protected from being
  -- swapped to the disk.


  -- | Version of copy which copies many entries.
  copyFromBytes :: Dest (Ptr w)
                -> Src  Pointer
                -> Int          -- ^ How many items.
                -> IO ()

instance EndianStore Word8 where
  store                  = poke . castPtr
  load                   = peek . castPtr
  copyFromBytes dest src = memcpy (castPtr <$> dest) src . (toEnum :: Int -> BYTES Int)

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
storeAt cptr offset = store $ offset <.> cptr

-- | Load the @n@-th value of an array pointed by the crypto pointer.
loadFromIndex :: EndianStore w
              => Pointer -- ^ the pointer to the first element of
                         -- the array
              -> Int     -- ^ the index of the array
              -> IO w
{-# INLINE loadFromIndex #-}

loadFromIndex cptr index = loadP undefined
  where loadP ::  EndianStore w => w -> IO w
        loadP w = loadFrom cptr offset
          where offset = toEnum index * byteSize w

-- | Load from a given offset. The offset is given in type safe units.
loadFrom :: ( EndianStore w
            , LengthUnit offset
            )
         => Pointer  -- ^ the pointer
         -> offset   -- ^ the offset
         -> IO w
{-# INLINE loadFrom #-}
loadFrom cptr offset = load $ offset <.> cptr

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
  c_loadLE32 :: Pointer  -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE32"
  c_storeLE32 :: Pointer -> Word32 -> IO ()

foreign import ccall unsafe "raaz/core/endian.h raazCopyFromLE32"
  c_copyFromLE32 ::  Dest (Ptr (LE Word32)) -> Src Pointer -> Int -> IO ()

instance EndianStore (LE Word32) where
  load             = fmap LE .  c_loadLE32
  store ptr (LE w) = c_storeLE32 ptr w
  copyFromBytes    = c_copyFromLE32

------------------- Endian store for BE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE32"
  c_loadBE32 :: Pointer -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE32"
  c_storeBE32 :: Pointer -> Word32 -> IO ()

foreign import ccall unsafe "raaz/core/endian.h raazCopyFromBE32"
  c_copyFromBE32 :: Dest (Ptr (BE Word32)) -> Src Pointer -> Int -> IO ()

instance EndianStore (BE Word32) where
  load             = fmap BE .  c_loadBE32
  store ptr (BE w) = c_storeBE32 ptr w
  copyFromBytes    = c_copyFromBE32

------------------- Endian store for LE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE64"
  c_loadLE64 :: Pointer -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE64"
  c_storeLE64 :: Pointer -> Word64 -> IO ()

foreign import ccall unsafe "raaz/core/endian.h raazCopyFromLE64"
  c_copyFromLE64 :: Dest (Ptr (LE Word64)) -> Src Pointer -> Int -> IO ()

instance EndianStore (LE Word64) where
  load             = fmap LE .  c_loadLE64
  store ptr (LE w) = c_storeLE64 ptr w
  copyFromBytes    =  c_copyFromLE64

------------------- Endian store for BE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE64"
  c_loadBE64 :: Pointer -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE64"
  c_storeBE64 :: Pointer -> Word64 -> IO ()

foreign import ccall unsafe "raaz/core/endian.h raazCopyFromBE64"
  c_copyFromBE64 :: Dest (Ptr (BE Word64)) -> Src Pointer -> Int -> IO ()

instance EndianStore (BE Word64) where
  load             = fmap BE .  c_loadBE64
  store ptr (BE w) = c_storeBE64 ptr w
  copyFromBytes    = c_copyFromBE64

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
