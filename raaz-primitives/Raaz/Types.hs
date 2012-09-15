{-|

Some basic types and classes used in the cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
module Raaz.Types
       ( CryptoCoerce(..)
       -- * Endian safe types
       -- $endianSafe
       , cryptoAlignment, CryptoAlign, CryptoPtr
       , CryptoStore(..), toByteString
       , Word32LE, Word32BE
       , Word64LE, Word64BE
       ) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Typeable(Typeable)
import Foreign.Ptr
import Foreign.Storable
import System.Endian

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

-- | Often we would like to feed the output of one crypto algorithm as
-- the input of the other algorithm, for e.g RSA sign the HMAC of a
-- message.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t


-- | This class is defined mainly to perform endian safe loading and
-- storing. For any type that might have to be encoded as either byte
-- strings or peeked/poked from a memory location it is advisable to
-- define an instance of this class. Using store and load will then
-- prevent endian confusion.
class Storable w => CryptoStore w where
  store :: CryptoPtr -> w -> IO ()
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
   deriving ( Bounded, Enum, Read, Show, Integral
            , Num, Real, Eq, Ord, Bits, Storable
            , Typeable
            )

-- | Big endian  `Word32`
newtype Word32BE = BE32 Word32
   deriving ( Bounded, Enum, Read, Show, Integral
            , Num, Real, Eq, Ord, Bits, Storable
            , Typeable
            )

-- | Little endian `Word64`
newtype Word64LE = LE64 Word64
   deriving ( Bounded, Enum, Read, Show, Integral
            , Num, Real, Eq, Ord, Bits, Storable
            , Typeable
            )

-- | Big endian `Word64`
newtype Word64BE = BE64 Word64
   deriving ( Bounded, Enum, Read, Show, Integral
            , Num, Real, Eq, Ord, Bits, Storable
            , Typeable
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
