{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts  #-}

-- | Internal module that has the encode class and some utility functions.
module Raaz.Core.Encode.Internal
       ( Encodable(..), Format(..)
       , encode, decode, unsafeDecode
       , between, isDigit
       ) where


import Data.Maybe

import Data.ByteString              (ByteString)
import Data.ByteString.Internal     (unsafeCreate, c2w)
import Data.String
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Prelude hiding               (length)
import System.IO.Unsafe   (unsafePerformIO)

import Raaz.Core.Classes
import Raaz.Core.Util.ByteString(length, withByteString)
import Raaz.Core.Util.Ptr(byteSize)

-- | A binary encoding format is something for which there is a 1:1
-- correspondence with bytestrings. We also insist that it is an
-- instance of `IsString`, so that it can be easily included in source
-- code, and `Show`, so that it can be easily printed out.
class (IsString fmt, Show fmt) => Format fmt where
  encodeByteString :: ByteString -> fmt
  decodeFormat     :: fmt        -> ByteString

-- | Bytestring itself is an encoding format (namely binary format).
instance Format ByteString where
  encodeByteString = id
  {-# INLINE encodeByteString #-}
  decodeFormat     = id
  {-# INLINE decodeFormat     #-}

-- | Stuff that can be encoded into byte strings.
class Encodable a where
  -- | Convert stuff to bytestring
  toByteString          :: a           -> ByteString

  -- | Try parsing back a value. Returns nothing on failure.
  fromByteString        :: ByteString  -> Maybe a

  -- | Unsafe version of `fromByteString`
  unsafeFromByteString  :: ByteString  -> a

  default toByteString :: EndianStore a => a -> ByteString
  toByteString w = unsafeCreate (sizeOf w) putit
    where putit ptr = store (castPtr ptr) w


  default fromByteString :: EndianStore a => ByteString -> Maybe a
  fromByteString bs | byteSize proxy == length bs = Just w
                         | otherwise                   = Nothing
         where w = unsafePerformIO $ withByteString bs (load . castPtr)
               proxy = undefined `asTypeOf` w

  unsafeFromByteString = fromMaybe (error "fromByteString error") . fromByteString

instance Encodable ByteString where
  toByteString         = id
  {-# INLINE toByteString #-}
  fromByteString       = Just . id
  {-# INLINE fromByteString #-}
  unsafeFromByteString = id
  {-# INLINE unsafeFromByteString #-}

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


-- | Check whether a given word8 is in a given range of characters.
between :: Char -> Char -> Word8 -> Bool
between low high = \ x -> x >= c2w low && x <= c2w high
{-# INLINE between #-}

-- | Check whether it is a valid digit.
isDigit :: Word8 -> Bool
{-# INLINE isDigit #-}
isDigit = between '0' '9'
