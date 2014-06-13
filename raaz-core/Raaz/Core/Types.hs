{-|

This module provide some basic types and type classes used in the
cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TemplateHaskell            #-}

module Raaz.Core.Types
       (
         -- * Type safety.
         -- $typesafety$

         -- ** Endian safe types
         -- $endianSafe$

         -- ** Type safe lengths
         -- $length$
         Word32LE, Word32BE
       , Word64LE, Word64BE
       , EndianStore(..), toByteString

       , BYTES(..), BITS(..)
       , CryptoCoerce(..)
       , LengthUnit(..), inBits, atLeast, atMost
       , bitsQuotRem, bytesQuotRem
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
--      240 whether it is `Word32LE` or `Word32BE` or just `Word32`.
--
--   2. The normal arithmetic work on them.
--
--   3. They have the same printed form except for the constructor
--      sticking around.
--
-- Therefore, as far as Haskell programmers are concerned, `Word32LE`
-- and `Word32BE` should be treated as `Word32` for all algorithmic
-- aspects. Similarly, `Word64LE` and `Word64BE` should be treated as
-- `Word64`.
--
-- When defining other endian sensitive data types like hashes, we
-- expect users to use these endian safe types. For example SHA1 can
-- be defined as
--
-- > data SHA1 = SHA1 Word32BE Word32BE Word32BE Word32BE Word32BE
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



-- | Little endian `Word32`.
newtype Word32LE = LE32 Word32
   deriving ( Arbitrary, Bounded, Enum, Read, Show
            , Integral, Num, Real, Eq, Ord, Bits
            , Storable, Typeable
            )

-- | Big endian  `Word32`
newtype Word32BE = BE32 Word32
   deriving ( Arbitrary, Bounded, Enum, Read, Show
            , Integral, Num, Real, Eq, Ord, Bits
            , Storable, Typeable
            )

-- | Little endian `Word64`
newtype Word64LE = LE64 Word64
   deriving ( Arbitrary, Bounded, Enum, Read, Show
            , Integral, Num, Real, Eq, Ord, Bits
            , Storable, Typeable
            )

-- | Big endian `Word64`
newtype Word64BE = BE64 Word64
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
toWord32LE   :: Word32 -> Word32LE
{-# INLINE toWord32LE #-}
toWord32LE = LE32 . toLE32

-- | Convert a Word32LE to Word32
fromWord32LE :: Word32LE -> Word32
{-# INLINE fromWord32LE #-}
fromWord32LE (LE32 w) = fromLE32 w

-- | Convert a Word32 to its bigendian form.
toWord32BE :: Word32 -> Word32BE
{-# INLINE toWord32BE #-}
toWord32BE = BE32 . toBE32

-- | Convert a Word32BE to Word32
fromWord32BE :: Word32BE -> Word32
{-# INLINE fromWord32BE #-}
fromWord32BE (BE32 w) = fromBE32 w


-- | Convert a Word64 to its little endian form.
toWord64LE :: Word64 -> Word64LE
{-# INLINE toWord64LE #-}
toWord64LE = LE64 . toLE64

-- | Convert a Word64LE to Word64
fromWord64LE :: Word64LE -> Word64
{-# INLINE fromWord64LE #-}
fromWord64LE (LE64 w) = fromLE64 w

-- | Convert a Word64 to its bigendian form.
toWord64BE :: Word64 -> Word64BE
{-# INLINE toWord64BE #-}
toWord64BE = BE64 . toBE64

-- | Convert a Word64BE to Word64
fromWord64BE :: Word64BE -> Word64
{-# INLINE fromWord64BE #-}
fromWord64BE (BE64 w) = fromBE64 w

instance EndianStore Word32LE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord32LE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord32LE


instance EndianStore Word32BE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord32BE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord32BE


instance EndianStore Word64LE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord64LE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord64LE

instance EndianStore Word64BE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord64BE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord64BE

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

-- | Type class capturing type safe length units. Minimal complete
-- implementation @`inBytes`@.
class (Num u, Enum u) => LengthUnit u where
  -- | Express the length units in bytes.
  inBytes :: u -> BYTES Int

instance  LengthUnit (BYTES Int) where
  inBytes = id
  {-# INLINE inBytes #-}

-- | Express the length units in bits.
inBits  :: LengthUnit u => u -> BITS Word64
inBits u = BITS $ 8 * (fromIntegral  by)
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

bytesQuotRem :: LengthUnit u
             => BYTES Int
             -> (u , BYTES Int)
bytesQuotRem bytes = (u , r)
  where divisor = inBytes (1 `asTypeOf` u)
        (q, r)  = bytes `quotRem` divisor
        u       = toEnum $ fromEnum q

bitsQuotRem :: LengthUnit u
             => BITS Word64
             -> (u , BITS Word64)

bitsQuotRem bits = (u , r)
  where divisor = inBits (1 `asTypeOf` u)
        (q, r)  = bits `quotRem` divisor
        u       = toEnum $ fromEnum q

------------------  Coercion of types ------------------------------

-- | Often it is possible to convert (encode) values of type @s@ as
-- values of type @t@. In such a case, it is advisable to define an
-- instance of this class.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t


instance CryptoCoerce Word32 Word32LE where
  cryptoCoerce = LE32

instance CryptoCoerce Word32 Word32BE where
  cryptoCoerce = BE32

instance CryptoCoerce Word64 Word64LE where
  cryptoCoerce = LE64

instance CryptoCoerce Word64 Word64BE where
  cryptoCoerce = BE64

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
