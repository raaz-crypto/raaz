{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE CPP                        #-}

-- | This module exposes types that builds in type safety into some of
-- the low level pointer operations. The functions here are pretty low
-- level and will be required only by developers of the library that
-- to the core of the library.
module Raaz.Core.Types.Pointer
       ( -- * Pointers, offsets, and alignment
         Pointer
         -- ** Type safe length units.
       , LengthUnit(..)
       , BYTES(..), BITS(..), inBits
       , sizeOf
         -- *** Some length arithmetic
       , bitsQuotRem, bytesQuotRem
       , bitsQuot, bytesQuot
       , atLeast, atMost
         -- ** Types measuring alignment
       , Alignment, wordAlignment
       , ALIGN
       , alignment, alignPtr, movePtr, alignedSizeOf, nextAlignedPtr, peekAligned, pokeAligned
         -- ** Allocation functions.
       , allocaAligned, allocaSecureAligned, allocaBuffer, allocaSecure, mallocBuffer
         -- ** Some buffer operations
       , memset, memmove, memcpy
       , hFillBuf
       ) where



import           Control.Applicative
import           Control.Exception     ( bracket_)
import           Control.Monad         ( void, when )
import           Control.Monad.IO.Class
import           Data.Monoid
import           Data.Word
import           Foreign.Marshal.Alloc
import           Foreign.Ptr           ( Ptr         )
import qualified Foreign.Ptr           as FP
import           Foreign.Storable      ( Storable, peek, poke )
import qualified Foreign.Storable      as FS
import           System.IO             (hGetBuf, Handle)

import Prelude -- To stop the annoying warnings of Applicatives and Monoids.

import Raaz.Core.MonoidalAction
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



-- Developers notes: I assumes that word alignment is alignment
-- safe. If this is not the case one needs to fix this to avoid
-- performance degradation or worse incorrect load/store.


-- | A type whose only purpose in this universe is to provide
-- alignment safe pointers.
newtype Align = Align Word deriving Storable

-- | The pointer type used by all cryptographic library.
type Pointer = Ptr Align


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
                 , Real, Num, Storable
                 )

-- | Type safe lengths/offsets in units of bits.
newtype BITS  a  = BITS  a
        deriving ( Show, Eq, Equality, Ord, Enum, Integral
                 , Real, Num, Storable
                 )

-- | Type safe length unit that measures offsets in multiples of word
-- length. This length unit can be used if one wants to make sure that
-- all offsets are word aligned.
newtype ALIGN    = ALIGN { unALIGN :: Int }
                 deriving ( Show, Eq,Ord, Enum, Integral
                          , Real, Num, Storable
                          )

instance Num a => Monoid (BYTES a) where
  mempty  = 0
  mappend = (+)

instance Monoid ALIGN where
  mempty  = ALIGN 0
  mappend x y = ALIGN $ unALIGN x + unALIGN y

instance LengthUnit ALIGN where
  inBytes (ALIGN x) = BYTES $ x * FS.alignment (undefined :: Align)
  {-# INLINE inBytes #-}

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

------------------------ Alignment --------------------------------

-- | Types to measure alignment in units of bytes.
newtype Alignment = Alignment { unAlignment :: Int }
        deriving ( Show, Eq, Ord, Enum, Integral
                 , Real, Num
                 )

-- | The default alignment to use is word boundary.
wordAlignment :: Alignment
wordAlignment = alignment (undefined :: Align)

instance Monoid Alignment where
  mempty  = Alignment 1
  mappend = lcm


---------- Type safe versions of some pointer functions -----------------

-- | Compute the size of a storable element.
sizeOf :: Storable a => a -> BYTES Int
sizeOf = BYTES . FS.sizeOf

-- | Size of the buffer to be allocated to store an element of type
-- @a@ so as to guarantee that there exist enough space to store the
-- element after aligning the pointer. If the size of the element is
-- @s@ and its alignment is @a@ then this quantity is essentially
-- equal to @s + a - 1@. All units measured in word alignment.
alignedSizeOf  :: Storable a => a -> ALIGN
alignedSizeOf a =  s + pad - 1
  where -- The size of the element in Align units.
        s    = atLeast $ sizeOf a
        -- Alignment adjusted to word boundary.
        algn = wordAlignment   <> alignment a
        pad  = atLeast $ BYTES  $ unAlignment $ algn

-- | Compute the alignment for a storable object.
alignment :: Storable a => a -> Alignment
alignment =  Alignment . FS.alignment

-- | Align a pointer to the appropriate alignment.
alignPtr :: Ptr a -> Alignment -> Ptr a
alignPtr ptr = FP.alignPtr ptr . unAlignment

-- | Move the given pointer with a specific offset.
movePtr :: LengthUnit l => Ptr a -> l -> Ptr a
movePtr ptr l = FP.plusPtr ptr offset
  where BYTES offset = inBytes l

-- | Compute the next aligned pointer starting from the given pointer
-- location.
nextAlignedPtr :: Storable a => Ptr a -> Ptr a
nextAlignedPtr ptr = alignPtr ptr $ alignment $ elementOfPtr ptr
  where elementOfPtr :: Ptr b -> b
        elementOfPtr _ = undefined

-- | Peek the element from the next aligned location.
peekAligned :: Storable a => Ptr a -> IO a
peekAligned = peek . nextAlignedPtr

-- | Poke the element from the next aligned location.
pokeAligned     :: Storable a => Ptr a -> a -> IO ()
pokeAligned ptr =  poke $ nextAlignedPtr ptr

-- | The expression @allocaAligned a l action@ allocates a local
-- buffer of length @l@ and alignment @a@ and passes it on to the IO
-- action @action@. No explicit freeing of the memory is required as
-- the memory is allocated locally and freed once the action
-- finishes. It is better to use this function than
-- @`allocaBytesAligned`@ as it does type safe scaling and alignment.
allocaAligned :: LengthUnit l
              => Alignment          -- ^ the alignment of the buffer
              -> l                  -- ^ size of the buffer
              -> (Pointer -> IO b)  -- ^ the action to run
              -> IO b
allocaAligned algn l = allocaBytesAligned b a
  where BYTES     b = inBytes l
        Alignment a = algn


-- | This function allocates a chunk of "secure" memory of a given
-- size and runs the action. The memory (1) exists for the duration of
-- the action (2) will not be swapped during that time and (3) will be
-- wiped clean and deallocated when the action terminates either
-- directly or indirectly via errors. While this is mostly secure,
-- there can be strange situations in multi-threaded application where
-- the memory is not wiped out. For example if you run a
-- crypto-sensitive action inside a child thread and the main thread
-- gets exists, then the child thread is killed (due to the demonic
-- nature of haskell threads) immediately and might not give it chance
-- to wipe the memory clean. This is a problem inherent to how the
-- `bracket` combinator works inside a child thread.
--
-- TODO: File this insecurity in the wiki.
--
allocaSecureAligned :: LengthUnit l
                    => Alignment
                    -> l
                    -> (Pointer -> IO a)
                    -> IO a

#ifdef HAVE_MLOCK

foreign import ccall unsafe "sys/mman.h mlock"
  c_mlock :: Pointer -> BYTES Int -> IO Int


foreign import ccall unsafe "sys/mman.h munlock"
  c_munlock :: Pointer -> BYTES Int -> IO ()

allocaSecureAligned a l action = allocaAligned a l actualAction
  where sz = inBytes l
        actualAction cptr = let
          lockIt    = do c <- c_mlock cptr sz
                         when (c /= 0) $ fail "secure memory: unable to lock memory"
          releaseIt =  memset cptr 0 l >>  c_munlock cptr sz
          in bracket_ lockIt releaseIt $ action cptr

#else
allocaSecureAligned _ _ = fail "memory locking not supported on this platform"

#endif
-- | A less general version of `allocaAligned` where the pointer passed
-- is aligned to word boundary.
allocaBuffer :: LengthUnit l
             => l                  -- ^ buffer length
             -> (Pointer -> IO b)  -- ^ the action to run
             -> IO b
{-# INLINE allocaBuffer #-}
allocaBuffer = allocaAligned wordAlignment

-- | A less general version of `allocaSecureAligned` where the pointer passed
-- is aligned to word boundary
allocaSecure :: LengthUnit l
             => l
             -> (Pointer -> IO b)
             -> IO b
allocaSecure = allocaSecureAligned wordAlignment

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

foreign import ccall unsafe "string.h memmove" c_memmove
    :: Dest Pointer -> Src Pointer -> BYTES Int -> IO Pointer

-- | Move between pointers.
memmove :: (MonadIO m, LengthUnit l)
        => Dest Pointer -- ^ destination
        -> Src Pointer  -- ^ source
        -> l            -- ^ Number of Bytes to copy
        -> m ()
memmove dest src = liftIO . void . c_memmove dest src . inBytes
{-# SPECIALIZE memmove :: Dest Pointer -> Src Pointer -> BYTES Int -> IO () #-}

foreign import ccall unsafe "string.h memset" c_memset
    :: Pointer -> Word8 -> BYTES Int -> IO Pointer

-- | Sets the given number of Bytes to the specified value.
memset :: (MonadIO m, LengthUnit l)
       => Pointer -- ^ Target
       -> Word8     -- ^ Value byte to set
       -> l         -- ^ Number of bytes to set
       -> m ()
memset p w = liftIO . void . c_memset p w . inBytes
{-# SPECIALIZE memset :: Pointer -> Word8 -> BYTES Int -> IO () #-}
