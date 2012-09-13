{-|

Some basic types and classes used in the cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Types
       ( Buffer
       , CryptoInput (..)
       , CryptoOutput(..)
       , CryptoCoerce(..)
       -- * Endian safe types
       -- $endianSafe
       , Word32LE, Word32BE
       , Word64LE, Word64BE
       ) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.Vector.Storable.Mutable as VSM
import Foreign.Ptr
import Foreign.Storable
import System.Endian

-- | A mutable buffer of bytes.
type Buffer = VSM.IOVector Word8

-- | A type that can be the input of any crypto algorithm.
class CryptoInput a where
  -- | Convert from a given bytestring.
  fromByteString :: ByteString -> Maybe a

  -- | Reads an element from the given buffer. This operation is
  -- unsafe because we normally avoid bound checking to improve
  -- speed. Use this only when you can prove that the index is withing
  -- the bound of the buffer.
  unsafeBufferRead :: Buffer -- ^ The buffer to read from
                   -> Int    -- ^ At what location in the buffer
                   -> IO a


-- | This is the class that captures anything that can be the output
-- of a crypto algorithm.
class CryptoOutput a where
  -- | Convert the type to Bytestring. This is always required to
  -- succeed.
  toByteString :: a -> ByteString

  -- | Writes the element to the given buffer. This operation is
  -- unsafe because we normally avoid bound checking to improve
  -- speed. Use this only when you can prove that the index is within
  -- the bound of the buffer.
  unsafeBufferWrite :: Buffer  -- ^ The buffer to write to
                    -> Int     -- ^ The index to write at
                    -> a       -- ^ The value to put in.
                    -> IO ()
-- | Often we would like to feed the input of one crypto algorithm as
-- the output of the other algorithm, for e.g RSA sign the HMAC of a
-- message.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t


{-

Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}


-- $endianSafe
--
-- To avoid endianness confusion in cryptographic algorithms, we
-- provide explicitly endianness encoded `Word32` and `Word64`
-- types. These types inherit their parent type's `Num` instance
-- (besides `Ord`, `Eq` etc). The advantage is the following
-- uniformity in their usage in Haskell code:
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
-- There is only one exception to this: The Storable instances of
-- their types guarantees proper endian conversion while peeking and
-- poking values. Peeking a `Word32LE` whose value is 0xFF would give
-- the bytes @0xFF 0x00 0x00 0x00@, whereas peeking a `Word32BE` gives
-- the bytes @0x00 0x00 0x00 0xFF@ irrespective of the underlying
-- machine. This is precisely what is intended: Endianness is relevant
-- only at the time of Load/Store and not at the time of
-- arithmetic. In contrast, peeking `Word32` gives either of the two
-- depending on the underlying machine.
--


-- | Little endian `Word32`.
newtype Word32LE = LE32 Word32
   deriving (Bounded, Enum, Eq, Integral, Num, Ord, Read, Real, Show, Bits)

-- | Big endian  `Word32`
newtype Word32BE = BE32 Word32
   deriving (Bounded, Enum, Eq, Integral, Num, Ord, Read, Real, Show, Bits)

-- | Little endian `Word64`
newtype Word64LE = LE64 Word64
   deriving (Bounded, Enum, Eq, Integral, Num, Ord, Read, Real, Show, Bits)

-- | Big endian `Word64`
newtype Word64BE = BE64 Word64
   deriving (Bounded, Enum, Eq, Integral, Num, Ord, Read, Real, Show, Bits)


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

-- | Guaranteed to peek and poke as little endian encoded 32-bit
-- positive integer.
instance Storable Word32LE where
  sizeOf         _ = sizeOf    (undefined :: Word32)
  {-# INLINE sizeOf      #-}
  alignment      _ = alignment (undefined :: Word32)
  {-# INLINE alignment   #-}

  peekElemOff ptr off = toWord32LE `fmap` peekElemOff (castPtr ptr) off
  {-# INLINE peekElemOff #-}
  peekByteOff ptr off = toWord32LE `fmap` peekByteOff ptr off
  {-# INLINE peekByteOff #-}
  peek = fmap toWord32LE . peek . castPtr
  {-# INLINE peek        #-}


  pokeElemOff ptr off = pokeElemOff (castPtr ptr) off . fromWord32LE
  {-# INLINE pokeElemOff #-}
  pokeByteOff ptr off = pokeByteOff ptr off . fromWord32LE
  {-# INLINE pokeByteOff #-}
  poke ptr = poke (castPtr ptr) . fromWord32LE
  {-# INLINE poke        #-}


-- | Guaranteed to peek and poke as big endian encoded 32-bit positive
-- integer.
instance Storable Word32BE where
  sizeOf         _ = sizeOf    (undefined :: Word32)
  {-# INLINE sizeOf      #-}
  alignment      _ = alignment (undefined :: Word32)
  {-# INLINE alignment   #-}

  peekElemOff ptr off = toWord32BE `fmap` peekElemOff (castPtr ptr) off
  {-# INLINE peekElemOff #-}
  peekByteOff ptr off = toWord32BE `fmap` peekByteOff (castPtr ptr) off
  {-# INLINE peekByteOff #-}
  peek = fmap toWord32BE . peek . castPtr
  {-# INLINE peek        #-}

  pokeElemOff ptr off = pokeElemOff (castPtr ptr) off . fromWord32BE
  {-# INLINE pokeElemOff #-}
  pokeByteOff ptr off = pokeByteOff ptr off . fromWord32BE
  {-# INLINE pokeByteOff #-}
  poke ptr = poke (castPtr ptr) . fromWord32BE
  {-# INLINE poke        #-}


-- | Guaranteed to peek and poke as little endian encoded 64-bit
-- positive integer.
instance Storable Word64LE where
  sizeOf         _ = sizeOf    (undefined :: Word64)
  {-# INLINE sizeOf      #-}
  alignment      _ = alignment (undefined :: Word64)
  {-# INLINE alignment   #-}

  peekElemOff ptr off = toWord64LE `fmap` peekElemOff (castPtr ptr) off
  {-# INLINE peekElemOff #-}
  peekByteOff ptr off = toWord64LE `fmap` peekByteOff ptr off
  {-# INLINE peekByteOff #-}
  peek = fmap toWord64LE . peek . castPtr
  {-# INLINE peek        #-}


  pokeElemOff ptr off = pokeElemOff (castPtr ptr) off . fromWord64LE
  {-# INLINE pokeElemOff #-}
  pokeByteOff ptr off = pokeByteOff ptr off . fromWord64LE
  {-# INLINE pokeByteOff #-}
  poke ptr = poke (castPtr ptr) . fromWord64LE
  {-# INLINE poke        #-}

-- | Guaranteed to peek and poke as big endian encoded 64-bit positive
-- integer.
instance Storable Word64BE where
  sizeOf         _ = sizeOf    (undefined :: Word64)
  {-# INLINE sizeOf      #-}
  alignment      _ = alignment (undefined :: Word64)
  {-# INLINE alignment   #-}
  peekElemOff ptr off = toWord64BE `fmap` peekElemOff (castPtr ptr) off
  {-# INLINE peekElemOff #-}
  peekByteOff ptr off = toWord64BE `fmap` peekByteOff ptr off
  {-# INLINE peekByteOff #-}
  peek = fmap toWord64BE . peek . castPtr
  {-# INLINE peek        #-}


  pokeElemOff ptr off = pokeElemOff (castPtr ptr) off . fromWord64BE
  {-# INLINE pokeElemOff #-}
  pokeByteOff ptr off = pokeByteOff ptr off . fromWord64BE
  {-# INLINE pokeByteOff #-}
  poke ptr = poke (castPtr ptr) . fromWord64BE
  {-# INLINE poke        #-}
