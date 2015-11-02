{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts  #-}

-- | Internal module that has the encode class and some utility functions.
module Raaz.Core.Encode.Internal
       ( Encodable(..), Format(..)
       , encode, decode, unsafeDecode
       ) where


import Data.Maybe

import Data.ByteString              (ByteString)
import Data.ByteString.Internal     (unsafeCreate)
import Data.String
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Prelude hiding               (length)
import System.IO.Unsafe   (unsafePerformIO)

import Raaz.Core.Types.Endian
import Raaz.Core.Types.Length
import Raaz.Core.Util.ByteString(length, withByteString)
import Raaz.Core.Util.Ptr(byteSize)


-- | Stuff that can be encoded into byte strings.
class Encodable a where
  -- | Convert stuff to bytestring
  toByteString          :: a           -> ByteString

  -- | Try parsing back a value. Returns nothing on failure.
  fromByteString        :: ByteString  -> Maybe a

  -- | Unsafe version of `fromByteString`
  unsafeFromByteString  :: ByteString  -> a

  default toByteString :: EndianStore a => a -> ByteString
  toByteString w    = unsafeCreate (sizeOf w) putit
    where putit ptr = store (castPtr ptr) w


  default fromByteString :: EndianStore a => ByteString -> Maybe a
  fromByteString bs  | byteSize proxy == length bs = Just w
                     | otherwise                   = Nothing
         where w     = unsafePerformIO $ withByteString bs (load . castPtr)
               proxy = undefined `asTypeOf` w

  unsafeFromByteString = fromMaybe (error "fromByteString error") . fromByteString

instance Encodable (LE Word32)
instance Encodable (LE Word64)
instance Encodable (BE Word32)
instance Encodable (BE Word64)

instance Encodable ByteString where
  toByteString         = id
  {-# INLINE toByteString #-}
  fromByteString       = Just . id
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


-- | A binary encoding format is something for which there is a 1:1
-- correspondence with bytestrings. We also insist that it is an
-- instance of `IsString`, so that it can be easily included in source
-- code, and `Show`, so that it can be easily printed out.
class (IsString fmt, Show fmt, Encodable fmt) => Format fmt where
  encodeByteString :: ByteString -> fmt
  decodeFormat     :: fmt        -> ByteString

-- | Bytestring itself is an encoding format (namely binary format).
instance Format ByteString where
  encodeByteString = id
  {-# INLINE encodeByteString #-}
  decodeFormat     = id
  {-# INLINE decodeFormat     #-}


-- | Encode in a given format.
encode :: (Encodable a, Format fmt) => a -> fmt
encode = encodeByteString . toByteString

-- | Decode from a given format. It results in Nothing if there is a
-- parse error.
decode :: (Format fmt, Encodable a) => fmt -> Maybe a
decode = fromByteString . decodeFormat

-- | The unsafe version of `decodeMaybe`.
unsafeDecode :: (Format fmt, Encodable a) => fmt -> a
unsafeDecode = unsafeFromByteString . decodeFormat
