{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts  #-}

-- | Internal module that has the encode class and some utility functions.
module Raaz.Core.Encode.Internal
       ( Encodable(..), Format(..)
       ) where

import Data.Maybe

import           Data.ByteString              (ByteString)
import           Data.ByteString.Internal     (unsafeCreate)
import           Data.String
import           Data.Word
import           Foreign.Ptr
import Prelude hiding               (length)
import System.IO.Unsafe   (unsafePerformIO)

import Raaz.Core.Types.Endian
import Raaz.Core.Types.Pointer
import Raaz.Core.Util.ByteString(length, withByteString)


-- | The type class `Encodable` captures all the types that can be
-- encoded into a stream of bytes. For a user defined type say @Foo@,
-- defining an instance `Encodable` is all that is required to make
-- use of `encode` and `decode` for any of the supported encoding
-- formats (i.e. instances of the class `Format`).
--
-- Minimum complete definition for this class is `toByteString` and
-- `fromByteString`. Instances of `EndianStore` have default
-- definitions for both these functions and hence a trivial instance
-- declaration is sufficient for such types.
--
-- > newtype Foo = Foo (LE Word64) deriving (Storable, EndianStore)
-- >
-- > instance EndianStore Foo where
-- >   ...
-- >
-- > instance Encodable Foo
-- >
--
-- In particular, all the endian encoded versions of Haskell's word,
-- i.e types like @`LE` Word32@, @`LE` Word64@ etc, are instances of
-- `Encodable`. Note that the corresponding plain type is /not/ an
-- instance of `Encodable` because encoding of say `Word32` without
-- specifying whether the endianness is meaningless.
--
class Encodable a where
  -- | Convert stuff to bytestring
  toByteString          :: a           -> ByteString

  -- | Try parsing back a value. Returns nothing on failure.
  fromByteString        :: ByteString  -> Maybe a

  -- | Unsafe version of `fromByteString`
  unsafeFromByteString  :: ByteString  -> a

  default toByteString :: EndianStore a => a -> ByteString
  toByteString w    = unsafeCreate (fromEnum $ sizeOf (pure w)) putit
    where putit ptr = store (castPtr ptr) w


  default fromByteString :: EndianStore a => ByteString -> Maybe a
  fromByteString bs  | sizeOf proxy == length bs   = Just w
                     | otherwise                   = Nothing
         where w     = unsafePerformIO $ withByteString bs (load . castPtr)
               proxy = pure w

  unsafeFromByteString = fromMaybe (error "fromByteString error") . fromByteString

instance Encodable Word8
instance Encodable (LE Word32)
instance Encodable (LE Word64)
instance Encodable (BE Word32)
instance Encodable (BE Word64)

instance Encodable ByteString where
  toByteString         = id
  {-# INLINE toByteString #-}
  fromByteString       = Just
  {-# INLINE fromByteString #-}
  unsafeFromByteString = id
  {-# INLINE unsafeFromByteString #-}

instance Encodable a => Encodable (BITS a) where
  toByteString (BITS a) = toByteString a
  fromByteString        = fmap BITS . fromByteString
  unsafeFromByteString  = BITS      . unsafeFromByteString



instance Encodable a => Encodable (BYTES a) where
  toByteString         (BYTES a) = toByteString a
  fromByteString        = fmap BYTES . fromByteString
  unsafeFromByteString  = BYTES      . unsafeFromByteString



-- | A binary format is a representation of binary data often in
-- printable form. We distinguish between various binary formats at
-- the type level and each supported format corresponds to an instance
-- of the the class `Format`. The `encodeByteString` and
-- `decodeFormat` are required to satisfy the laws
--
-- > decodeFormat . encodeByteString = id
--
-- For type safety, the formats themselves are opaque types and hence
-- it is not possible to obtain the underlying binary data directly.
-- We require binary formats to be instances of the class `Encodable`,
-- with the combinators `toByteString` and `fromByteString` of the
-- `Encodable` class performing the actual encoding and decoding.
--
-- Instances of `Format` are required to be instances of `Show` and so
-- that the encoded format can be easily printed. They are also
-- required to be instances of `IsString` so that they can be easily
-- represented in Haskell source using the @OverloadedStrings@
-- extension.  However, be careful when using this due to the fact
-- that invalid encodings can lead to runtime errors.
--
class (IsString fmt, Show fmt, Encodable fmt) => Format fmt where

  -- | Encode binary data into the format. The return type gurantees
  -- that any binary data can indeed be encoded into a format.
  encodeByteString :: ByteString -> fmt

  -- | Decode the format to its associated binary
  -- representation. Notice that this function always succeeds: we
  -- assume that elements of the type `fmt` are valid encodings and
  -- hence the return type is `ByteString` instead of @`Maybe`
  -- ByteString@.
  decodeFormat     :: fmt        -> ByteString

-- | Bytestring itself is an encoding format (namely binary format).
instance Format ByteString where
  encodeByteString = id
  {-# INLINE encodeByteString #-}
  decodeFormat     = id
  {-# INLINE decodeFormat     #-}
