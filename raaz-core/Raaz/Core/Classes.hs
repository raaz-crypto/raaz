{-|

This module provide some basic types and type classes used in the
cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE CPP                        #-}

#include "MachDeps.h"

module Raaz.Core.Classes
       (
         -- * Type safety.
         -- $typesafety$

         -- ** Endian safe types
         -- $endianSafe$

         -- ** Type safe lengths
         -- $length$
       , EndianStore(..), toByteString

       , BYTES(..), BITS(..)
       , CryptoCoerce(..)
       , LengthUnit(..), inBits, atLeast, atMost
       , bitsQuotRem, bytesQuotRem
       , bitsQuot, bytesQuot
       , EqWord(..), (===)

       -- * Cryptographic pointers and buffers.
       , cryptoAlignment, CryptoAlign, CryptoPtr
       , ForeignCryptoPtr
       , CryptoBuffer(..), withCryptoBuffer
       , HasName(..)
       ) where

import Data.Bits
import Data.Word
import Data.ByteString          (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Typeable            (Typeable, typeOf)
import Foreign.Ptr
import Foreign.Storable
import Foreign.ForeignPtr.Safe  (ForeignPtr)

import System.Endian
import Test.QuickCheck          (Arbitrary)

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
-- 3. Ways to write timing safe equality checks.


-- $endianSafe$
--
-- One of the most common source of implementation problems in crypto
-- algorithms is the correct dealing of endianness. Endianness matters
-- only when we first load the data from the buffer or when we finally
-- write the data out. For types that are meant to be serialised, the
-- EndianStore instance in defined in such a way that the `load` and
-- `store` takes care of endian coversion automatically.
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



-- | A class that facilitates the definition of timing resistant
-- equality checking.
class EqWord a where
  -- | The value @`eqWord` a1 a2@ is guranteed to be 0 if @a1@ and
  -- @a2@ are equal and non-zero otherwise. Besides instances should
  -- ensure that the computation of @eqWord@ is timing resistant.
  eqWord :: a -> a -> Word

-- | A timing resistant variant of `==` for instances of `EqWord`.
(===) :: EqWord a => a -> a -> Bool
(===) a b = eqWord a b == 0


instance EqWord Word where
  eqWord = xor

instance EqWord Word8 where
  eqWord w1 w2 = fromIntegral $ xor w1 w2

instance EqWord Word16 where
  eqWord w1 w2 = fromIntegral $ xor w1 w2

instance EqWord Word32 where
  eqWord w1 w2 = fromIntegral $ xor w1 w2


instance EqWord Word64 where
-- It assumes that Word size is atleast 32 Bits
#if WORD_SIZE_IN_BITS < 64
  eqWord w1 w2 = (w11 `xor` w21) .|. (w12 `xor` w22)
    where
      w11 = fromIntegral $ w1 `shiftR` 32
      w12 = fromIntegral $ w1
      w21 = fromIntegral $ w2 `shiftR` 32
      w22 = fromIntegral $ w2
#else
  eqWord w1 w2 = fromIntegral $ xor w1 w2
#endif
instance ( EqWord a
         , EqWord b
         ) => EqWord (a,b) where
  eqWord (a,b) (a',b') = eqWord a a' .|.
                         eqWord b b'

instance ( EqWord a
         , EqWord b
         , EqWord c
         ) => EqWord (a,b,c) where
  eqWord (a,b,c) (a',b',c') = eqWord a a' .|.
                              eqWord b b' .|.
                              eqWord c c'

instance ( EqWord a
         , EqWord b
         , EqWord c
         , EqWord d
         ) => EqWord (a,b,c,d) where
  eqWord (a,b,c,d) (a',b',c',d') = eqWord a a' .|.
                                   eqWord b b' .|.
                                   eqWord c c' .|.
                                   eqWord d d'

instance ( EqWord a
         , EqWord b
         , EqWord c
         , EqWord d
         , EqWord e
         ) => EqWord (a,b,c,d,e) where
  eqWord (a,b,c,d,e) (a',b',c',d',e') = eqWord a a' .|.
                                        eqWord b b' .|.
                                        eqWord c c' .|.
                                        eqWord d d' .|.
                                        eqWord e e'

instance ( EqWord a
         , EqWord b
         , EqWord c
         , EqWord d
         , EqWord e
         , EqWord f
         ) => EqWord (a,b,c,d,e,f) where
  eqWord (a,b,c,d,e,f) (a',b',c',d',e',f') = eqWord a a' .|.
                                             eqWord b b' .|.
                                             eqWord c c' .|.
                                             eqWord d d' .|.
                                             eqWord e e' .|.
                                             eqWord f f'

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
        deriving ( Arbitrary, Show, Eq, EqWord, Ord, Enum, Integral
                 , Real, Num, Storable, EndianStore
                 )

-- | Type safe lengths/offsets in units of bits. If the function
-- excepts a length unit of a different type use `cryptoCoerce` to
-- convert to a more convenient length units.  The `CrytoCoerce`
-- instance is guranteed to do the appropriate scaling.
newtype BITS  a  = BITS  a
        deriving ( Arbitrary, Show, Eq, EqWord, Ord, Enum, Integral
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

--------------------  Types that have a name ----------------------

-- | Types which have names. This is mainly used in test cases and
-- benchmarks to get the name of the primitive. A default instance is
-- provided for types with `Typeable` instances.
class HasName a where
  getName :: a -> String
  default getName :: Typeable a => a -> String
  getName = show . typeOf

instance HasName Word32
instance HasName Word64
-------------------------------------------------------------------
