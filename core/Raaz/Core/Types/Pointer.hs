{-# OPTIONS_HADDOCK hide                #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE TypeFamilies               #-}

-- | This module exposes types that builds in type safety into some of
-- the low level pointer operations. The functions here are pretty low
-- level and will be required only by developers of the core of the
-- library.
module Raaz.Core.Types.Pointer
       ( -- * Pointers, offsets, and alignment
         -- $basics$
         -- ** Type safe length units.
         LengthUnit(..)
       , BYTES(..)
         -- *** Some length functions.
       , atLeast, atLeastAligned, atMost
       --  ** Type safe functions on Ptr
       , Ptr
       , sizeOf, alignment, alignedSizeOf
       , movePtr, alignPtr, nextLocation
       , peekAligned, pokeAligned

         -- ** The class of pointer types.
       , Pointer(..), unsafeWithPointer
       , AlignedPtr (..) , ptrAlignment, nextAlignedPtr
       , allocaBuffer, allocaSecure
         -- ** Some low level pointer actions
       , wipeMemory
       , memset
       , memcpy
       , hFillBuf
       ) where



import           Control.Exception     ( bracket_ )

import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Foreign.Marshal.Alloc
import           Foreign.Ptr           ( Ptr, castPtr         )
import qualified Foreign.Ptr           as FP
import           Foreign.Storable      ( Storable, peek, poke )
import qualified Foreign.Storable      as FS
import           GHC.TypeLits

import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM

import Raaz.Core.Prelude
import Raaz.Core.Types.Equality
import Raaz.Core.Types.Copying

-- $basics$
--
-- The main concepts introduced here are the following
--
-- [`Pointer`:] The generic pointer type that is used through the
-- library.
--
-- [`LengthUnit`:] This class captures types units of length.
--
-- [`Alignment`:] A dedicated type that is used to keep track of
-- alignment constraints.  offsets in We have the generic pointer type
-- `Pointer` and distinguish between different length units at the
-- type level. This helps in to avoid a lot of length conversion
-- errors.

-------------------------- Length Units --------- -------------------

-- | In cryptographic settings, we need to measure pointer offsets and
-- buffer sizes. The smallest of length/offset that we have is bytes
-- measured using the type `BYTES`. In various other circumstances, it
-- would be more natural to measure these in multiples of bytes. For
-- example, when allocating buffer to use encrypt using a block cipher
-- it makes sense to measure the buffer size in multiples of block of
-- the cipher. Explicit conversion between these length units, while
-- allocating or moving pointers, involves a lot of low level scaling
-- that is also error prone. To avoid these errors due to unit
-- conversions, we distinguish between different length units at the
-- type level. This type class capturing all such types, i.e. types
-- that stand of length units. Allocation functions and pointer
-- arithmetic are generalised to these length units.
--
-- All instances of a `LengthUnit` are required to be instances of
-- `Monoid` where the monoid operation gives these types the natural
-- size/offset addition semantics: i.e. shifting a pointer by offset
-- @a `mappend` b@ is same as shifting it by @a@ and then by @b@.
class (Enum u, Monoid u) => LengthUnit u where
  -- | Express the length units in bytes.
  inBytes :: u -> BYTES Int

-- | Type safe lengths/offsets in units of bytes.
newtype BYTES a  = BYTES a
        deriving ( Show, Eq, Equality, Ord, Enum, Integral
                 , Real, Num, Storable, Bounded, Bits
                 )

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

---------- Type safe versions of some pointer functions -----------------

-- | Compute the size of a storable element.
sizeOf :: Storable a => Proxy a -> BYTES Int
sizeOf = BYTES . FS.sizeOf . asProxyTypeOf undefined

-- | Compute the alignment for a storable object.
alignment :: Storable a => Proxy a -> Alignment
alignment =  Alignment . FS.alignment . asProxyTypeOf undefined

-- | Move the given pointer with a specific offset.
movePtr :: LengthUnit l => Ptr a -> l -> Ptr a
movePtr ptr l = FP.plusPtr ptr offset
  where BYTES offset = inBytes l

-- | Align pointer to the next alignment
alignPtr :: Storable a => Ptr a -> Alignment -> Ptr a
alignPtr ptr = FP.alignPtr ptr . unAlignment

-- | Size of the buffer to be allocated to store an element of type
-- @a@ so as to guarantee that there exist enough space to store the
-- element after aligning the pointer.
alignedSizeOf  :: Storable a => Proxy a -> BYTES Int
alignedSizeOf aproxy =  atLeastAligned (sizeOf aproxy) $ alignment aproxy

-- | Compute the next aligned pointer starting from the given pointer
-- location.
nextLocation :: Storable a => Ptr a -> Ptr a
nextLocation ptr = alignPtr ptr $ alignment $ getProxy ptr
  where getProxy :: Ptr b -> Proxy b
        getProxy  = const Proxy

-- | Peek the element from the next aligned location.
peekAligned :: Storable a => Ptr a -> IO a
peekAligned = peek . nextLocation

-- | Poke the element from the next aligned location.
pokeAligned     :: Storable a => Ptr a -> a -> IO ()
pokeAligned ptr =  poke $ nextLocation ptr

instance LengthUnit (BYTES Int) where
  inBytes = id
  {-# INLINE inBytes #-}

-- | Express length unit @src@ in terms of length unit @dest@ rounding
-- upwards.
atLeast :: ( LengthUnit src
           , LengthUnit dest
           )
        => src
        -> dest
atLeast src | r == 0    = u
            | otherwise = succ u
    where (u , r) = bytesQuotRem $ inBytes src


-- | Often we want to allocate a buffer of size @l@. We also want to
-- make sure that the buffer starts at an alignment boundary
-- @a@. However, the standard word allocation functions might return a
-- pointer that is not aligned as desired. The @atLeastAligned l a@
-- returns a length @n@ such the length @n@ is big enough to ensure
-- that there is at least @l@ length of valid buffer starting at the
-- next pointer aligned at boundary @a@. If the alignment required in
-- @a@ then allocating @l + a@ should do the trick.
--
-- NOTE: Let us say that the next allocation happens at a pointer ptr
-- whose address is r mod a. Then if we allocate a buffer of size s,
-- the buffer will be spanning the address ptr, ptr + 1, ... ptr + s
-- -1.  Assume that r ≠ 0, then the next address at which our buffer
-- can start is at ptr + a - r. Therefore the size of the buffer
-- available at this location is (ptr + s - 1) - (ptr + a - r ) + 1 =
-- s - a + r, which should at least l. Therefore, we have s - a - r =
-- l, which means s >= l + a - r. This is maximised when r = 1.  This
-- analysis means that we need to allocate only l + a - 1 bytes but
-- that seems to be creating problems for our copy. May be it is a
-- memcpy vs memmove problem.
atLeastAligned :: LengthUnit l => l -> Alignment -> BYTES Int
atLeastAligned l a = n <> pad
  where n    = atLeast l
        pad  = BYTES $ unAlignment a

-- | Express length unit @src@ in terms of length unit @dest@ rounding
-- downwards.
atMost :: ( LengthUnit src
          , LengthUnit dest
          )
       => src
       -> dest
atMost = fst . bytesQuotRem . inBytes

-- | A length unit @u@ is usually a multiple of bytes. The function
-- `bytesQuotRem` is like `quotRem`: the value @byteQuotRem bytes@ is
-- a tuple @(x,r)@, where @x@ is @bytes@ expressed in the unit @u@
-- with @r@ being the reminder.
bytesQuotRem :: LengthUnit u
             => BYTES Int
             -> (u , BYTES Int)
bytesQuotRem bytes = (u , r)
  where divisor       = inBytes (toEnum 1 `asTypeOf` u)
        (BYTES q, r)  = bytes `quotRem` divisor
        u             = toEnum q

-- | Depending on the constraints of various pointers, raaz expose a
-- variety of pointer types. This type class capturing such types. The
-- main operation of interest to use is casting and allocation. All of
-- these types have an underlying pointer which you can also be
-- accessed.
class Pointer (ptr :: * -> *) where

  -- | Convert pointers of one type to another.
  castPointer  :: ptr a -> ptr b


  -- | The `alloca` variant for this pointer type. The action
  -- @allocaPointer l action@ allocates a buffer of size @l@ and
  -- passes it on to @action@. No explicit de-allocation is required
  -- just like in the case of `alloca`
  allocaPointer :: BYTES Int        -- size to allocate
                -> (ptr a  -> IO b) -- action to run
                -> IO b
  --
  -- | Recover the underlying raw pointer.
  unsafeRawPtr :: ptr a -> Ptr a

instance Pointer Ptr where
  unsafeRawPtr             = id
  {-# INLINE  unsafeRawPtr #-}
  castPointer              = castPtr
  {-# INLINE castPointer   #-}
  allocaPointer (BYTES sz) = allocaBytes sz

-- | Lifts raw pointer actions to the given pointer type.
unsafeWithPointer :: Pointer ptr => (Ptr a -> b) -> ptr a -> b
unsafeWithPointer action = action . unsafeRawPtr

-- | Allocate a buffer for an action that expects a generic
-- pointer. Length can be specified in any length units.
allocaBuffer :: ( LengthUnit l, Pointer ptr)
             => l                  -- ^ buffer length
             -> (ptr something -> IO b)  -- ^ the action to run
             -> IO b
allocaBuffer = allocaPointer . inBytes


----------------- Secure allocation ---------------------------------

-- | Variant of `allocaBuffer` that allocates a locked buffer of a
-- given size and runs the action. The associated memory (1) exists
-- for the duration of the action (2) will not be swapped during the
-- action as guaranteed by the memlock function of the operating
-- system and (3) will be wiped clean and deallocated when the action
-- terminates either directly or indirectly via errors. While this is
-- mostly secure, there are still edge cases in multi-threaded
-- applications where the memory will not be cleaned. For example, if
-- you run a crypto-sensitive action inside a child thread and the
-- main thread gets exists, then the child thread is killed (due to
-- the demonic nature of threads in GHC haskell) immediately and might
-- not give it chance to wipe the memory clean. See
-- <https://ghc.haskell.org/trac/ghc/ticket/13891> on this problem and
-- possible workarounds.
--
allocaSecure :: ( LengthUnit l, Pointer ptr)
             => l
             -> (ptr a -> IO b)
             -> IO b
allocaSecure l action = allocaBuffer l actual
    where actual ptr    = bracket_ (lockIt ptr) (releaseIt ptr) $ action ptr
          lockIt ptr    = do c <- memlock ptr l
                             when (c /= 0) $ fail "secure memory: unable to lock memory"
                             -- TODO: Is this the best way to fail
                             -- when no secure memory is available ?
          releaseIt ptr = wipeMemory ptr l >>  memunlock ptr l

foreign import ccall unsafe "raaz/core/memory.h raazMemorylock"
  c_mlock :: Ptr a -> BYTES Int -> IO Int

foreign import ccall unsafe "raaz/core/memory.h raazMemoryunlock"
  c_munlock :: Ptr a -> BYTES Int -> IO ()

foreign import ccall unsafe "raazWipeMemory" c_wipe_memory
    :: Ptr a -> BYTES Int -> IO ()

memlock :: (LengthUnit l, Pointer ptr)
        => ptr a
        -> l
        -> IO Int
memlock   ptr = unsafeWithPointer c_mlock ptr . inBytes

memunlock :: (LengthUnit l, Pointer ptr)
          => ptr a
          -> l
          -> IO ()
memunlock ptr = unsafeWithPointer c_munlock ptr . inBytes

-- | Cleanup the given pointer of any sensitive data. This is a tricky
-- function to write as compilers are known to optimise this away. In
-- our case we try to use the platform specific one if it exists.
wipeMemory :: (LengthUnit l, Pointer ptr)
            => ptr a   -- ^ buffer to wipe
            -> l       -- ^ buffer length
            -> IO ()
wipeMemory p = void . unsafeWithPointer c_wipe_memory p . inBytes

{-# SPECIALIZE memlock    :: Ptr a -> BYTES Int -> IO Int  #-}
{-# SPECIALIZE memunlock  :: Ptr a -> BYTES Int -> IO ()   #-}
{-# SPECIALISE wipeMemory :: Ptr a -> BYTES Int -> IO ()   #-}



-------------------- Low level pointer operations ------------------

-- | A version of `hGetBuf` which works for any type safe length units.
hFillBuf :: (LengthUnit bufSize, Pointer ptr)
         => Handle
         -> ptr a
         -> bufSize
         -> IO (BYTES Int)
{-# INLINE hFillBuf #-}
hFillBuf handle ptr bufSize = BYTES <$> hGetBuf handle (unsafeRawPtr ptr) bytes
  where BYTES bytes = inBytes bufSize

------------------- Copy move and set contents ----------------------------

-- | Some common PTR functions abstracted over type safe length.
foreign import ccall unsafe "string.h memcpy" c_memcpy
    :: Dest (Ptr dest) -> Src (Ptr src) -> BYTES Int -> IO (Ptr ())

-- | Copy between pointers.
memcpy :: (LengthUnit l, Pointer ptrS, Pointer ptrD)
       => Dest (ptrD dest) -- ^ destination
       -> Src  (ptrS src)  -- ^ src
       -> l               -- ^ Number of Bytes to copy
       -> IO ()
memcpy dest src = void . c_memcpy destRaw srcRaw . inBytes
  where destRaw = unsafeRawPtr <$> dest
        srcRaw  = unsafeRawPtr <$> src

{-# SPECIALIZE memcpy :: Dest (Ptr dest) -> Src (Ptr src) -> BYTES Int -> IO () #-}

foreign import ccall unsafe "string.h memset" c_memset
    :: Ptr buf -> Word8 -> BYTES Int -> IO (Ptr ())

-- | Sets the given number of Bytes to the specified value.
memset :: (LengthUnit l, Pointer ptr)
       => ptr a     -- ^ Target
       -> Word8     -- ^ Value byte to set
       -> l         -- ^ Number of bytes to set
       -> IO ()
memset p w = void . unsafeWithPointer c_memset p w . inBytes
{-# SPECIALIZE memset :: Ptr a -> Word8 -> BYTES Int -> IO () #-}

-- | The type @AlignedPtr n@ that captures pointers that are aligned
-- to @n@ byte boundary.
newtype AlignedPtr (n :: Nat) a = AlignedPtr { forgetAlignment :: Ptr a}

instance KnownNat n => Pointer (AlignedPtr n) where
  unsafeRawPtr  = forgetAlignment
  {-# INLINE unsafeRawPtr #-}
  castPointer   = AlignedPtr . castPtr . forgetAlignment
  {-# INLINE castPointer #-}

  allocaPointer (BYTES sz) action =
    allocaBytesAligned sz algn (action . AlignedPtr)
    where algn  = fromEnum $ natVal $ getProxy action
          getProxy :: (AlignedPtr n a -> IO b) -> Proxy n
          getProxy _ = Proxy

-- | Given a raw pointer (i.e. element of type `Ptr`), returns the
-- next pointer aligned to @n@-bytes boundary.
nextAlignedPtr :: (Storable a, KnownNat n) => Ptr a -> AlignedPtr n a
nextAlignedPtr = alignIt
  where alignIt ptr = AlignedPtr
                      $ alignPtr ptr
                      $ ptrAlignment
                      $ getProxy alignIt
        getProxy :: (Ptr a -> AlignedPtr n a) -> Proxy (AlignedPtr n a)
        getProxy _  = Proxy

-- | Compute the alignment restriction.
ptrAlignment :: KnownNat n => Proxy (AlignedPtr n a) -> Alignment
ptrAlignment = Alignment . fromEnum . natVal . coerce
  where coerce :: Proxy (AlignedPtr n a) -> Proxy n
        coerce = const Proxy
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
