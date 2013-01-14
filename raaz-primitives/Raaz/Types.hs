{-|

Some basic types and classes used in the cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
module Raaz.Types
       ( CryptoCoerce(..)
       , cryptoAlignment, CryptoAlign, CryptoPtr
       , CryptoStore(..), toByteString
       -- * Endian safe types
       -- $endianSafe
       , Word32LE, Word32BE
       , Word64LE, Word64BE
       -- * Length encoding
       -- $length
       , BYTES(..), BITS(..)
       -- * Types capturing implementations
       -- $implementation
       , HaskellGHC(..), MagicHash(..), C99FFI(..), C99GCC(..),
       ) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Typeable(Typeable)
import Foreign.Ptr
import Foreign.Storable
import System.Endian
import Test.QuickCheck(Arbitrary(..))

-- Developers notes: I assumes that word alignment is alignment
-- safe. If this is not the case one needs to fix this to avoid
-- performance degradation or worse incorrect load/store.

-- | A type whose only purpose in this universe is to provide
-- alignment safe pointers.
newtype CryptoAlign = CryptoAlign Word deriving Storable

-- | Alignment safe pointers.
type CryptoPtr = Ptr CryptoAlign

-- | Alignment to use for cryptographic pointers.
cryptoAlignment :: Int
cryptoAlignment = alignment (undefined :: CryptoAlign)
{-# INLINE cryptoAlignment #-}

-- | Often we need a type safe way to convert between one type to
-- another. In such a case, it is advisable to define an instance of
-- this class. One place where it is extensively used is in type safe
-- lengths.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t


-- | This class is defined mainly to perform endian safe loading and
-- storing. For any type that might have to be encoded as either byte
-- strings or peeked/poked from a memory location it is advisable to
-- define an instance of this class. Using store and load will then
-- prevent endian confusion.
class Storable w => CryptoStore w where

  -- | Store the given value at the locating pointed by the pointer
  store :: CryptoPtr   -- ^ the location.
        -> w           -- ^ value to store
        -> IO ()

  -- | Load the value from the location pointed by the pointer.
  load  :: CryptoPtr -> IO w

-- | Generate a bytestring representation of the object.
toByteString :: CryptoStore w => w -> ByteString
toByteString w = unsafeCreate (sizeOf w) putit
      where putit ptr = store (castPtr ptr) w

{-

Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}


-- $endianSafe
--
-- One of the most common source of implementation problems in crypto
-- algorithms is the correct dealing of endianness. We define the
-- class `CryptoStore` to solve this problem in a type safe way. Any
-- type that might have to be encoded as either byte strings or
-- peeked/poked from a memory location should be an instance of this
-- class.
--
-- This module also provide explicitly endianness encoded versions of
-- Word32 and Word64 which are instances of `CryptoStore`. These types
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
-- `Word64`. One can use the load/store functions to encode them
-- safely as well.

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

instance CryptoStore Word32LE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord32LE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord32LE


instance CryptoStore Word32BE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord32BE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord32BE


instance CryptoStore Word64LE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord64LE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord64LE

instance CryptoStore Word64BE where
  {-# INLINE load  #-}
  {-# INLINE store #-}
  load      = fmap toWord64BE . peek . castPtr
  store ptr = poke (castPtr ptr) . fromWord64BE

-- $length
--
-- Crypto protocols also represent message lengths in various units,
-- bytes and bits usually. To catch length conversion errors at
-- compile time, we include the following types that specify
-- explicitly whether the length is in bits or bytes.

-- | Type safe lengths/offsets in units of bytes. If the function
-- excepts a length unit of a different type use `cryptoCoerce` to
-- convert to a more convenient length units.  the `CrytoCoerce`
-- instance is guranteed to do the appropriate scaling.
newtype BYTES a  = BYTES a
        deriving ( Arbitrary, Show, Eq, Ord, Enum, Integral
                 , Real, Num, Storable, CryptoStore
                 )

-- | Type safe lengths/offsets in units of bits. If the function
-- excepts a length unit of a different type use `cryptoCoerce` to
-- convert to a more convenient length units.  the `CrytoCoerce`
-- instance is guranteed to do the appropriate scaling.
newtype BITS  a  = BITS  a
        deriving ( Arbitrary, Show, Eq, Ord, Enum, Integral
                 , Real, Num, Storable, CryptoStore
                 )

instance ( Integral by
         , Num bi
         )
         => CryptoCoerce (BYTES by) (BITS bi) where
  cryptoCoerce (BYTES by) = BITS $ 8 * fromIntegral by
  {-# INLINE cryptoCoerce #-}

-- | BEWARE: If the number of bits is not an integral multiple of 8
-- then there are rounding errors.
instance ( Integral bi
         , Real bi
         , Num by
         )
         => CryptoCoerce (BITS bi) (BYTES by) where
  cryptoCoerce (BITS bi) = BYTES $ fromIntegral (bi `quot` 8)
  {-# INLINE cryptoCoerce #-}

instance ( Integral by1
         , Num by2
         ) => CryptoCoerce (BYTES by1) (BYTES by2) where
  cryptoCoerce (BYTES by) = BYTES $ fromIntegral by
  {-# INLINE cryptoCoerce #-}


instance ( Integral bi1
         , Num bi2
         ) => CryptoCoerce (BITS bi1) (BITS bi2) where
  cryptoCoerce (BITS bi) = BITS $ fromIntegral bi
  {-# INLINE cryptoCoerce #-}

-- $implementation
--
-- Each primitives have multiple implementations and these
-- implementations are characterised by types. Given below are the
-- standard implementation types.


-- | Captures implementation in GHC flavoured haskell.
data HaskellGHC = HaskellGHC deriving Show

-- | Captures implementations that uses the MagicHash unboxed types.
data MagicHash = MagicHash deriving Show

-- | Captures implementations using portable C99 and Haskell FFI.
data C99FFI = C99FFI       deriving Show

-- | Captures implementation which assumes GCC. Use this if you are
-- using some gcc specific features like inline assembly etc.
data C99GCC = C99GCC       deriving Show
