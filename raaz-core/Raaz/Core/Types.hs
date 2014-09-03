{-|

This module provide some basic types and type classes used in the
cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}

module Raaz.Core.Types
       (
         -- * Type safety.
         -- $typesafety$

         -- ** Endian safe types
         -- $endianSafe$

         -- ** Type safe lengths
         -- $length$
         LE, BE
       , EndianStore(..), toByteString

       , BYTES(..), BITS(..)
       , CryptoCoerce(..)
       , LengthUnit(..), inBits, atLeast, atMost
       , bitsQuotRem, bytesQuotRem
       , bitsQuot, bytesQuot
       , cryptoAlignment, CryptoAlign, CryptoPtr
       , ForeignCryptoPtr
       , CryptoBuffer(..), withCryptoBuffer
       ) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Typeable(Typeable)
import Foreign.Ptr
import Foreign.Storable
import Foreign.ForeignPtr.Safe (ForeignPtr)
import System.Endian
import Test.QuickCheck(Arbitrary)

-- $typesafety$
--
-- One of the aims of raaz is to avoid many bugs by making use of the
-- type system of Haskell whenever possible. The types provided here
-- avoids two kinds of errors
--
-- 1. Endian mismatch errors.
--
-- 2. Length conversion errors.
--


-- $endianSafe$
--
-- One of the most common source of implementation problems in crypto
-- algorithms is the correct dealing of endianness. Endianness matters
-- only when we first load the data from the buffer or when we finally
-- write the data out. The class `EndianStore` via its member functions
-- `load` and `store` takes care of endian coversion automatically.
--
-- This module also provide explicitly endianness encoded versions of
-- Word32 and Word64 which are instances of `EndianStore`. These types
-- inherit their parent type's `Num` instance (besides `Ord`, `Eq`
-- etc). The advantage is the following uniformity in their usage in
-- Haskell code:
--
--   1. Numeric constants are represented in their Haskell notation
--      (which is big endian). For example 0xF0 represents the number
--      240 whether it is `(LE Word32)` or `(BE Word32)` or just `Word32`.
--
--   2. The normal arithmetic work on them.
--
--   3. They have the same printed form except for the constructor
--      sticking around.
--
-- Therefore, as far as Haskell programmers are concerned, `(LE Word32)`
-- and `(BE Word32)` should be treated as `Word32` for all algorithmic
-- aspects. Similarly, `(LE Word64)` and `(BE Word64)` should be treated as
-- `Word64`.
--
-- When defining other endian sensitive data types like hashes, we
-- expect users to use these endian safe types. For example SHA1 can
-- be defined as
--
-- > data SHA1 = SHA1 (BE Word32) (BE Word32) (BE Word32) (BE Word32) (BE Word32)
--
-- Then the EndianStore instance boils down to storing the words in
-- correct order.



-- | This class is defined mainly to perform endian safe loading and
-- storing. For any type that might have to be encoded as either byte
-- strings or peeked/poked from a memory location it is advisable to
-- define an instance of this class. Using store and load will then
-- prevent endian confusion.
class Storable w => EndianStore w where

  -- | Store the given value at the locating pointed by the pointer
  store :: CryptoPtr   -- ^ the location.
        -> w           -- ^ value to store
        -> IO ()

  -- | Load the value from the location pointed by the pointer.
  load  :: CryptoPtr -> IO w

-- | Generate a bytestring representation of the object.
toByteString :: EndianStore w => w -> ByteString
toByteString w = unsafeCreate (sizeOf w) putit
      where putit ptr = store (castPtr ptr) w

{-

Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}

-- | Little-endian wrapper for words
newtype LE w = LE w
    deriving ( Arbitrary, Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, Ord, Bits
             , Storable, Typeable
             )

-- | Big-endian wrapper for words
newtype BE w = BE w
    deriving ( Arbitrary, Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, Ord, Bits
             , Storable, Typeable
             )

{-|

Developers notes:

The next set of conversion functions are intensionally not exported
and are defined only to aid readability of the Storable instance
declaration. At first glance it might appear that they could be useful
but their export can cause confusion.

-}


-- | Convert a Word32 to its little endian form.
toWord32LE :: Word32 -> LE Word32
{-# INLINE toWord32LE #-}
toWord32LE = LE . toLE32

-- | Convert a little endian Word32 to Word32
fromWord32LE :: LE Word32 -> Word32
{-# INLINE fromWord32LE #-}
fromWord32LE (LE w) = fromLE32 w

-- | Convert a Word32 to its bigendian form.
toWord32BE :: Word32 -> BE Word32
{-# INLINE toWord32BE #-}
toWord32BE = BE . toBE32

-- | Convert a big endian Word32 to Word32
fromWord32BE :: BE Word32 -> Word32
{-# INLINE fromWord32BE #-}
fromWord32BE (BE w) = fromBE32 w


-- | Convert a Word64 to its little endian form.
toWord64LE :: Word64 -> LE Word64
{-# INLINE toWord64LE #-}
toWord64LE = LE . toLE64

-- | Convert a little endian Word64 to Word64
fromWord64LE :: LE Word64 -> Word64
{-# INLINE fromWord64LE #-}
fromWord64LE (LE w) = fromLE64 w

-- | Convert a Word64 to its bigendian form.
toWord64BE :: Word64 -> BE Word64
{-# INLINE toWord64BE #-}
toWord64BE = BE . toBE64

-- | Convert a big endian Word64 to Word64
fromWord64BE :: BE Word64 -> Word64
{-# INLINE fromWord64BE #-}
fromWord64BE (BE w) = fromBE64 w

loadConv :: Storable a => (a -> b) -> CryptoPtr -> IO b
{-# INLINE loadConv #-}
loadConv f = fmap f . peek . castPtr

storeConv :: Storable a => (b -> a) -> CryptoPtr -> b -> IO ()
{-# INLINE storeConv #-}
storeConv f ptr = poke (castPtr ptr) . f

instance EndianStore (LE Word32) where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load  = loadConv  toWord32LE
  store = storeConv fromWord32LE


instance EndianStore (BE Word32) where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load  = loadConv  toWord32BE
  store = storeConv fromWord32BE


instance EndianStore (LE Word64) where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load  = loadConv toWord64LE
  store = storeConv fromWord64LE

instance EndianStore (BE Word64) where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load  = loadConv toWord64BE
  store = storeConv fromWord64BE

-- $length$
--
-- The other source of errors is when we have length conversions. Some
-- times we need the length in bits (for example when appending the
-- pad bytes in a crypto-hash), in other instances we need them in
-- bytes (for example while allocating buffers). This module provides
-- the `BYTES` and `BITS` type which capture lengths in units of bytes
-- and BITS respectively.
--
-- Often we do want to measure lengths in other units like for example
-- multiples of block size. We say such units are type safe lengths if
-- they can be converted to BYTES and BITS with out any loss of
-- information. There is a possibility that these values can overflow
-- but if we assume that the lengths are reasonable (i.e. used in
-- contexts where we need to allocate a memory buffer or do some
-- pointer arithmetic) we would avoid a lot of bugs and boiler plate.
-- We capture these type safe lengths using the type class
-- `LengthUnit`.
--
-- Most, if not all, functions in raaz that accept a length argument
-- can be given any type safe length units. Thus a lot of length
-- conversion boilerplate can be eradicated.
--

-- | Type safe lengths/offsets in units of bytes. If the function
-- excepts a length unit of a different type use `cryptoCoerce` to
-- convert to a more convenient length units.  The `CrytoCoerce`
-- instance is guranteed to do the appropriate scaling.
newtype BYTES a  = BYTES a
        deriving ( Arbitrary, Show, Eq, Ord, Enum, Integral
                 , Real, Num, Storable, EndianStore
                 )

-- | Type safe lengths/offsets in units of bits. If the function
-- excepts a length unit of a different type use `cryptoCoerce` to
-- convert to a more convenient length units.  The `CrytoCoerce`
-- instance is guranteed to do the appropriate scaling.
newtype BITS  a  = BITS  a
        deriving ( Arbitrary, Show, Eq, Ord, Enum, Integral
                 , Real, Num, Storable, EndianStore
                 )

-- | Type class capturing type safe length units.
class (Num u, Enum u) => LengthUnit u where
  -- | Express the length units in bytes.
  inBytes :: u -> BYTES Int

instance  LengthUnit (BYTES Int) where
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
            | otherwise = u + 1
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
  where divisor = inBytes (1 `asTypeOf` u)
        (q, r)  = bytes `quotRem` divisor
        u       = toEnum $ fromEnum q

-- | Function similar to `bytesQuotRem` but returns only the quotient.
bytesQuot :: LengthUnit u
          => BYTES Int
          -> u
bytesQuot bytes = u
  where divisor = inBytes (1 `asTypeOf` u)
        q       = bytes `quot` divisor
        u       = toEnum $ fromEnum q


-- | Function similar to `bytesQuotRem` but works with bits instead.
bitsQuotRem :: LengthUnit u
            => BITS Word64
            -> (u , BITS Word64)
bitsQuotRem bits = (u , r)
  where divisor = inBits (1 `asTypeOf` u)
        (q, r)  = bits `quotRem` divisor
        u       = toEnum $ fromEnum q

-- | Function similar to `bitsQuotRem` but returns only the quotient.
bitsQuot :: LengthUnit u
         => BITS Word64
         -> u
bitsQuot bits = u
  where divisor = inBits (1 `asTypeOf` u)
        q       = bits `quot` divisor
        u       = toEnum $ fromEnum q

------------------  Coercion of types ------------------------------

-- | Often it is possible to convert (encode) values of type @s@ as
-- values of type @t@. In such a case, it is advisable to define an
-- instance of this class.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t

instance CryptoCoerce w (LE w) where
  cryptoCoerce = LE

instance CryptoCoerce w (BE w) where
  cryptoCoerce = BE

instance CryptoCoerce s t => CryptoCoerce (BITS s) (BITS t) where
  cryptoCoerce (BITS s) = BITS $ cryptoCoerce s

instance CryptoCoerce s t => CryptoCoerce (BYTES s)(BYTES t) where
  cryptoCoerce (BYTES s) = BYTES $ cryptoCoerce s

------------------ Alignment fu -------------------------------

-- Developers notes: I assumes that word alignment is alignment
-- safe. If this is not the case one needs to fix this to avoid
-- performance degradation or worse incorrect load/store.

-- | A type whose only purpose in this universe is to provide
-- alignment safe pointers.
newtype CryptoAlign = CryptoAlign Word deriving Storable

-- | Alignment safe pointers.
type CryptoPtr = Ptr CryptoAlign

-- | Alignment safe `ForeignPtr`.
type ForeignCryptoPtr = ForeignPtr CryptoAlign

-- | Alignment to use for cryptographic pointers.
cryptoAlignment :: Int
cryptoAlignment = alignment (undefined :: CryptoAlign)
{-# INLINE cryptoAlignment #-}

-- | Pointers with associated size. Reading and writing under the
-- given size is considered safe.
data CryptoBuffer = CryptoBuffer {-# UNPACK #-} !(BYTES Int)
                                 {-# UNPACK #-} !CryptoPtr

-- | Working on the pointer associated with the `CryptoBuffer`.
withCryptoBuffer :: CryptoBuffer -- ^ The buffer
                 -> (BYTES Int -> CryptoPtr -> IO b)
                                 -- ^ The action to perfrom
                 -> IO b
withCryptoBuffer (CryptoBuffer sz cptr) with = with sz cptr
