{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DefaultSignatures #-}

-- | Internal module that has the encode class and some utility functions.
module Raaz.Core.Encode.Internal
       ( Encode(..)
       , between, isDigit
       ) where


import Data.Maybe
import Data.ByteString              (ByteString)
import Data.ByteString.Internal     (unsafeCreate, c2w)
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Prelude hiding               (length)
import System.IO.Unsafe   (unsafePerformIO)

import Raaz.Core.Classes
import Raaz.Core.Util.ByteString(length, withByteString)
import Raaz.Core.Util.Ptr(byteSize)

class Encode a where
  -- | Encode
  encode        :: a           -> ByteString

  -- | Decode for the string representation. Can raise error if the
  -- input is not proper.
  decode        :: ByteString  -> a

  -- | Safer version of decode. Will result in |Nothing| if the
  -- input is not a proper enoding of an expected value.
  decodeMaybe   :: ByteString  -> Maybe a

  decode         = fromMaybe (error "decode error") . decodeMaybe

  -- | Default encoding of an endian store type.

  default encode :: EndianStore a => a -> ByteString
  encode w = unsafeCreate (sizeOf w) putit
    where putit ptr = store (castPtr ptr) w

  -- | Default decoding for an endian store type

  default decodeMaybe :: EndianStore a => ByteString -> Maybe a
  decodeMaybe bs | byteSize proxy == length bs = Just w
                 | otherwise                   = Nothing
         where w = unsafePerformIO $ withByteString bs (load . castPtr)
               proxy = undefined `asTypeOf` w


instance Encode (ByteString) where
  encode       = id
  decode       = id
  decodeMaybe  = Just . id

-- | Check whether a given word8 is in a given range of characters.
between :: Char -> Char -> Word8 -> Bool
between low high = \ x -> x >= c2w low && x <= c2w high
{-# INLINE between #-}

-- | Check whether it is a valid digit.
isDigit :: Word8 -> Bool
{-# INLINE isDigit #-}
isDigit = between '0' '9'
