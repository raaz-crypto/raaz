{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE TypeFamilies               #-}

-- | This module exposes types that builds in type safety into some of
-- the low level pointer operations. The functions here are pretty low
-- level and will be required only by developers of the core of the
-- library.
module Raaz.Core.Types.Pointer
       ( -- * Pointers, offsets, and alignment
         Pointer, AlignedPointer, AlignedPtr(..), onPtr, ptrAlignment, nextAlignedPtr
         -- ** Type safe length units.
       , LengthUnit(..)
       , BYTES(..), BITS(..), BLOCKS(..), blocksOf, inBits
       , sizeOf
         -- *** Some length arithmetic
       , bitsQuotRem, bytesQuotRem
       , bitsQuot, bytesQuot
       , atLeast, atLeastAligned, atMost
         -- ** Types measuring alignment
       , Alignment, wordAlignment
       , alignment, alignPtr, movePtr, alignedSizeOf, nextLocation, peekAligned, pokeAligned
         -- ** Allocation functions.
       , allocaBuffer, allocaAligned, allocaSecure
       , mallocBuffer
         -- ** Some buffer operations
       , memset
       , wipe_memory
       , memcpy
       , hFillBuf
       ) where



import           Control.Applicative
import           Control.Exception     ( bracket )
import           Control.Monad         ( void, when, liftM )
import           Control.Monad.IO.Class

#if !MIN_VERSION_base(4,8,0)
import Data.Monoid  -- Import only when base < 4.8.0
#endif

#if !MIN_VERSION_base(4,11,0)
import Data.Semigroup
#endif

import           Data.Bits                   ( Bits )
import           Data.Proxy
import           Data.Word
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Foreign.Marshal.Alloc
import           Foreign.Ptr           ( Ptr                  )
import qualified Foreign.Ptr           as FP
import           Foreign.Storable      ( Storable, peek, poke )
import qualified Foreign.Storable      as FS
import           GHC.TypeLits
import           System.IO             (hGetBuf, Handle)

import qualified Data.Vector.Generic         as GV
import qualified Data.Vector.Generic.Mutable as GVM

import Prelude -- To stop the annoying warnings of Applicatives and Monoids.

import Raaz.Core.Primitive
import Raaz.Core.MonoidalAction
import Raaz.Core.Types.Equality
import Raaz.Core.Types.Copying
import Raaz.Core.IOCont

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

-- | A newtype declaration so as to avoid orphan instances.
newtype Byte = BYTE Word8 deriving Storable

-- | The pointer type used by raaz.
type Pointer = Ptr Byte


-- | The type @AlignedPtr n@ that captures pointers that are aligned
-- to @n@ byte boundary.
newtype AlignedPtr (n :: Nat) a = AlignedPtr { forgetAlignment :: Ptr a}

type AlignedPointer n = AlignedPtr n Byte

-- | Run a pointer action on the associated aligned pointer.
onPtr :: (Ptr a -> b) -> AlignedPtr n a -> b
onPtr action = action . forgetAlignment

-- | Recover the alignment restriction of the pointer.
ptrAlignment :: (Storable a, KnownNat n) => Proxy (AlignedPtr n a) -> Alignment
ptrAlignment aptr = restriction <> alignment (getElementProxy aptr)
  where getAlignProxy :: Proxy (AlignedPtr n a) -> Proxy n
        getAlignProxy _ = Proxy
        getElementProxy :: Proxy (AlignedPtr n a) -> Proxy a
        getElementProxy _ = Proxy
        restriction = toEnum $ fromEnum $ natVal $ getAlignProxy aptr

nextAlignedPtr :: (Storable a, KnownNat n) => Ptr a -> AlignedPtr n a
nextAlignedPtr ptr = thisPtr
  where thisPtr = AlignedPtr $ alignPtr ptr $ ptrAlignment $ pure thisPtr

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

-- | Type safe lengths/offsets in units of bits.
newtype BITS  a  = BITS  a
        deriving ( Show, Eq, Equality, Ord, Enum, Integral
                 , Real, Num, Storable, Bounded
                 )

instance Num a => Semigroup (BYTES a) where
  (<>) = (+)

instance Num a => Monoid (BYTES a) where
  mempty  = 0
  mappend = (<>)

instance LengthUnit (BYTES Int) where
  inBytes = id
  {-# INLINE inBytes #-}

-- | Express the length units in bits.
inBits  :: LengthUnit u => u -> BITS Word64
inBits u = BITS $ 8 * fromIntegral by
  where BYTES by = inBytes u

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
-- @a@ then allocating @l + a - 1 should do the trick.
atLeastAligned :: LengthUnit l => l -> Alignment -> BYTES Int
atLeastAligned l a = n <> pad
  where n    = atLeast l
        pad  = BYTES  $ unAlignment a - 1


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

-- | Function similar to `bytesQuotRem` but returns only the quotient.
bytesQuot :: LengthUnit u
          => BYTES Int
          -> u
bytesQuot bytes = u
  where divisor = inBytes (toEnum 1 `asTypeOf` u)
        q       = bytes `quot` divisor
        u       = toEnum $ fromEnum q


-- | Function similar to `bytesQuotRem` but works with bits instead.
bitsQuotRem :: LengthUnit u
            => BITS Word64
            -> (u , BITS Word64)
bitsQuotRem bits = (u , r)
  where divisor = inBits (toEnum 1 `asTypeOf` u)
        (q, r)  = bits `quotRem` divisor
        u       = toEnum $ fromEnum q

-- | Function similar to `bitsQuotRem` but returns only the quotient.
bitsQuot :: LengthUnit u
         => BITS Word64
         -> u
bitsQuot bits = u
  where divisor = inBits (toEnum 1 `asTypeOf` u)
        q       = bits `quot` divisor
        u       = toEnum $ fromEnum q

-- | The most interesting monoidal action for us.
instance LengthUnit u => LAction u Pointer where
  a <.> ptr  = movePtr ptr a
  {-# INLINE (<.>) #-}


------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
newtype BLOCKS p = BLOCKS {unBLOCKS :: Int}
                 deriving (Show, Eq, Ord, Enum)

instance Semigroup (BLOCKS p) where
  (<>) x y = BLOCKS $ unBLOCKS x + unBLOCKS y
instance Monoid (BLOCKS p) where
  mempty   = BLOCKS 0
  mappend  = (<>)


instance Primitive p => LengthUnit (BLOCKS p) where
  inBytes p@(BLOCKS x) = scale * blockSize p
    where scale = BYTES x
          getProxy :: BLOCKS p -> Proxy (BlockSize p)
          getProxy _ = Proxy
          blockSize :: Primitive prim => BLOCKS prim -> BYTES Int
          blockSize  = toEnum . fromEnum . natVal . getProxy


-- | The expression @n `blocksOf` primProxy@ specifies the message
-- lengths in units of the block length of the primitive whose proxy
-- is @primProxy@. This expression is sometimes required to make the
-- type checker happy.
blocksOf :: Int -> Proxy p -> BLOCKS p
blocksOf n _ = BLOCKS n

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

  basicUnsafeRead  (MV_BYTES v) i             = BYTES `liftM` GVM.basicUnsafeRead v i
  basicUnsafeWrite (MV_BYTES v) i (BYTES x)   = GVM.basicUnsafeWrite v i x

  basicClear (MV_BYTES v)                     = GVM.basicClear v
  basicSet   (MV_BYTES v)         (BYTES x)   = GVM.basicSet v x

  basicUnsafeNew n                            = MV_BYTES `liftM` GVM.basicUnsafeNew n
  basicUnsafeReplicate n     (BYTES x)        = MV_BYTES `liftM` GVM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_BYTES v1) (MV_BYTES v2) = GVM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_BYTES v)   n            = MV_BYTES `liftM` GVM.basicUnsafeGrow v n

#if MIN_VERSION_vector(0,11,0)
  basicInitialize (MV_BYTES v)                = GVM.basicInitialize v
#endif



instance Unbox w => GV.Vector Vector (BYTES w) where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_BYTES v)            = V_BYTES  `liftM` GV.basicUnsafeFreeze v
  basicUnsafeThaw (V_BYTES v)               = MV_BYTES `liftM` GV.basicUnsafeThaw v
  basicLength (V_BYTES v)                   = GV.basicLength v
  basicUnsafeSlice i n (V_BYTES v)          = V_BYTES $ GV.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_BYTES v) i           = BYTES   `liftM`  GV.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_BYTES mv) (V_BYTES v) = GV.basicUnsafeCopy mv v
  elemseq _ (BYTES x)                       = GV.elemseq (undefined :: Vector a) x


------------------------ Alignment --------------------------------

-- | Types to measure alignment in units of bytes.
newtype Alignment = Alignment { unAlignment :: Int }
        deriving ( Show, Eq, Ord, Enum)

-- | The default alignment to use is word boundary.
wordAlignment :: Alignment
wordAlignment = alignment (Proxy :: Proxy Word8)



instance Semigroup Alignment where
  (<>) a b = Alignment $ lcm (unAlignment a) (unAlignment b)

instance Monoid Alignment where
  mempty  = Alignment 1
  mappend = (<>)


---------- Type safe versions of some pointer functions -----------------

-- | Compute the size of a storable element.
sizeOf :: Storable a => Proxy a -> BYTES Int
sizeOf = BYTES . FS.sizeOf . asProxyTypeOf undefined

-- | Size of the buffer to be allocated to store an element of type
-- @a@ so as to guarantee that there exist enough space to store the
-- element after aligning the pointer. If the size of the element is
-- @s@ and its alignment is @a@ then this quantity is essentially
-- equal to @s + a - 1@. All units measured in word alignment.
alignedSizeOf  :: Storable a => Proxy a -> BYTES Int
alignedSizeOf aproxy =  atLeastAligned (sizeOf aproxy) $ alignment aproxy

-- | Compute the alignment for a storable object.
alignment :: Storable a => Proxy a -> Alignment
alignment =  Alignment . FS.alignment . asProxyTypeOf undefined

-- | Align a pointer to the appropriate alignment.
alignPtr :: Ptr a -> Alignment -> Ptr a
alignPtr ptr = FP.alignPtr ptr . unAlignment



-- | Move the given pointer with a specific offset.
movePtr :: LengthUnit l => Ptr a -> l -> Ptr a
movePtr ptr l = FP.plusPtr ptr offset
  where BYTES offset = inBytes l

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

-------------------------- Lifting pointer actions  ---------------------------

-- | Allocate a buffer for an action that expects a pointer. Length
-- can be specified in any length units.
allocaBuffer :: (MonadIOCont m, LengthUnit l)
             => l                  -- ^ buffer length
             -> (Pointer -> m b)  -- ^ the action to run
             -> m b
allocaBuffer l = liftIOCont $ allocaBytes b
    where BYTES b = inBytes l

-- | Similar to `allocaBuffer` but for aligned pointers.
allocaAligned :: (MonadIOCont m, LengthUnit l, KnownNat n, Storable a)
              => l
              -> (AlignedPtr n a -> m b)
              -> m b

allocaAligned l action = liftIOCont (allocaBytesAligned b algn) $ action . AlignedPtr
    where getProxy :: (AlignedPtr n a -> m b) -> Proxy (AlignedPtr n a)
          getProxy _      = Proxy
          BYTES     b     = inBytes l
          Alignment algn  = ptrAlignment $ getProxy action

-- | This function allocates a chunk of "secure" memory of a given
-- size and runs the action. The memory (1) exists for the duration of
-- the action (2) will not be swapped during the action and (3) will
-- be wiped clean and deallocated when the action terminates either
-- directly or indirectly via errors. While this is mostly secure,
-- there are still edge cases in multi-threaded applications where the
-- memory will not be cleaned. For example, if you run a
-- crypto-sensitive action inside a child thread and the main thread
-- gets exists, then the child thread is killed (due to the demonic
-- nature of threads in GHC haskell) immediately and might not give it
-- chance to wipe the memory clean. See
-- <https://ghc.haskell.org/trac/ghc/ticket/13891> on this problem and
-- possible workarounds.
--
allocaSecure :: (MonadIOCont m, LengthUnit l)
             => l
             -> (Pointer -> m a)
             -> m a

allocaSecure l action = liftIOCont (allocaBuffer l) actualAction
    where actualAction cptr = liftIOCont (bracket (lockIt cptr) releaseIt) action
          sz                = inBytes l
          lockIt  cptr      = do c <- c_mlock cptr sz
                                 when (c /= 0) $ fail "secure memory: unable to lock memory"
                                 return cptr

          releaseIt cptr    = wipe_memory cptr l >>  c_munlock cptr sz






----------------- Secure allocation ---------------------------------

foreign import ccall unsafe "raaz/core/memory.h raazMemorylock"
  c_mlock :: Pointer -> BYTES Int -> IO Int

foreign import ccall unsafe "raaz/core/memory.h raazMemoryunlock"
  c_munlock :: Pointer -> BYTES Int -> IO ()



-- | Creates a memory of given size. It is better to use over
-- @`mallocBytes`@ as it uses typesafe length.
mallocBuffer :: LengthUnit l
             => l                    -- ^ buffer length
             -> IO Pointer
{-# INLINE mallocBuffer #-}
mallocBuffer l = mallocBytes bytes
  where BYTES bytes = inBytes l


-------------------- Low level pointer operations ------------------

-- | A version of `hGetBuf` which works for any type safe length units.
hFillBuf :: LengthUnit bufSize
         => Handle
         -> Pointer
         -> bufSize
         -> IO (BYTES Int)
{-# INLINE hFillBuf #-}
hFillBuf handle cptr bufSize = BYTES <$> hGetBuf handle cptr bytes
  where BYTES bytes = inBytes bufSize

------------------- Copy move and set contents ----------------------------

-- | Some common PTR functions abstracted over type safe length.
foreign import ccall unsafe "string.h memcpy" c_memcpy
    :: Dest Pointer -> Src Pointer -> BYTES Int -> IO Pointer

-- | Copy between pointers.
memcpy :: (MonadIO m, LengthUnit l)
       => Dest Pointer -- ^ destination
       -> Src  Pointer -- ^ src
       -> l            -- ^ Number of Bytes to copy
       -> m ()
memcpy dest src = liftIO . void . c_memcpy dest src . inBytes

{-# SPECIALIZE memcpy :: Dest Pointer -> Src Pointer -> BYTES Int -> IO () #-}

foreign import ccall unsafe "string.h memset" c_memset
    :: Pointer -> Word8 -> BYTES Int -> IO Pointer

wipe_memory :: (MonadIO m, LengthUnit l)
            => Pointer -- ^ buffer to wipe
            -> l       -- ^ buffer length
            -> m ()

#ifdef HAVE_EXPLICIT_BZERO
foreign import ccall unsafe "string.h explicit_bzero" c_wipe_memory
    :: Pointer -> BYTES Int -> IO Pointer
wipe_memory p = liftIO . void . c_wipe_memory p . inBytes

#elif defined HAVE_EXPLICIT_MEMSET
foreign import ccall unsafe "string.h memset" c_explicit_memset
    :: Pointer -> CInt-> BYTES Int -> IO Pointer
wipe_memory p = liftIO . void . c_explicit_memset p 0 . inBytes
#else
wipe_memory p = memset p 0  -- Not a safe option but the best that we
                            -- can do. Compiler hopefully not "smart"
                            -- enough to see dead code across
                            -- Haskell-C boundary.
#endif

-- | Sets the given number of Bytes to the specified value.
memset :: (MonadIO m, LengthUnit l)
       => Pointer -- ^ Target
       -> Word8     -- ^ Value byte to set
       -> l         -- ^ Number of bytes to set
       -> m ()
memset p w = liftIO . void . c_memset p w . inBytes
{-# SPECIALIZE memset :: Pointer -> Word8 -> BYTES Int -> IO () #-}
