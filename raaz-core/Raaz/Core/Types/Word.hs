{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DeriveDataTypeable         #-}


-- | This module also provide explicitly endianness encoded versions
-- of Word32 and Word64 which are instances of `EndianStore`. These
-- types inherit their parent type's `Num` instance (besides `Ord`,
-- `Eq` etc). The advantage is the following uniformity in their usage
-- in Haskell code:
--
--   1. Numeric constants are represented in their Haskell notation
--      (which is big endian). For example 0xF0 represents the number
--      240 whether it is @`LE` Word32@ or @`BE` Word32@ or just `Word32`.
--
--   2. The normal arithmetic work on them.
--
--   3. They have the same printed form except for the constructor
--      sticking around.
--
-- Therefore, as far as Haskell programmers are concerned, @`LE`
-- Word32@ and @`BE` Word32@ should be treated as `Word32` for all
-- algorithmic aspects. Similarly, @`LE` Word64@ and @`BE` Word64@
-- should be treated as `Word64`.
--
-- When defining other endian sensitive data types like hashes, we
-- expect users to use these endian safe types. For example SHA1 can
-- be defined as
--
-- > data SHA1 = SHA1 (BE Word32) (BE Word32) (BE Word32) (BE Word32) (BE Word32)
--
-- Then the `EndianStore` instance boils down to storing the words in
-- correct order.

module Raaz.Core.Types.Word
       ( LE, BE
       ) where

import Data.Bits
import Data.Typeable
import Data.Word
import Foreign.Storable
import Test.QuickCheck          (Arbitrary)
import Raaz.Core.Classes


{-

Developers notes:
-----------------

Make sure that the endian encoded version does not have any
performance penalty. We may have to stare at the core code generated
by ghc.

-}

-- | Little endian version of the word type @w@
newtype LE w = LE w
    deriving ( Arbitrary, Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, EqWord, Ord
             , Bits, Storable, Typeable
             )


-- | Big endian version of the word type @w@
newtype BE w = BE w
    deriving ( Arbitrary, Bounded, Enum, Read, Show
             , Integral, Num, Real, Eq, EqWord, Ord
             , Bits, Storable, Typeable
             )

instance HasName w => HasName (LE w) where
  getName (LE w) = "LE " ++ getName w

instance HasName w => HasName (BE w) where
  getName (BE w) = "BE " ++ getName w

instance CryptoCoerce w (LE w) where
  cryptoCoerce = LE

instance CryptoCoerce w (BE w) where
  cryptoCoerce = BE

------------------- Endian store for LE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE32"
  c_loadLE32 :: CryptoPtr -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE32"
  c_storeLE32 :: CryptoPtr -> Word32 -> IO ()

instance EndianStore (LE Word32) where
  load             = fmap LE .  c_loadLE32
  store ptr (LE w) = c_storeLE32 ptr w

------------------- Endian store for BE 32 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE32"
  c_loadBE32 :: CryptoPtr -> IO Word32

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE32"
  c_storeBE32 :: CryptoPtr -> Word32 -> IO ()

instance EndianStore (BE Word32) where
  load             = fmap BE .  c_loadBE32
  store ptr (BE w) = c_storeBE32 ptr w


------------------- Endian store for LE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadLE64"
  c_loadLE64 :: CryptoPtr -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreLE64"
  c_storeLE64 :: CryptoPtr -> Word64 -> IO ()

instance EndianStore (LE Word64) where
  load             = fmap LE .  c_loadLE64
  store ptr (LE w) = c_storeLE64 ptr w

------------------- Endian store for BE 64 ------------------------

foreign import ccall unsafe "raaz/core/endian.h raazLoadBE64"
  c_loadBE64 :: CryptoPtr -> IO Word64

foreign import ccall unsafe "raaz/core/endian.h raazStoreBE64"
  c_storeBE64 :: CryptoPtr -> Word64 -> IO ()

instance EndianStore (BE Word64) where
  load             = fmap BE .  c_loadBE64
  store ptr (BE w) = c_storeBE64 ptr w
