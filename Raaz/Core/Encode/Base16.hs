-- | Base 16 or hexadecimal encoding of objects.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Encode.Base16( Base16, fromBase16, showBase16 ) where

import Data.Char
import Data.Bits
import Data.String

import Data.ByteString as B
import Data.ByteString.Char8 as C8
import Data.ByteString.Internal (c2w )

import Data.ByteString.Unsafe(unsafeIndex)
import Data.Word
import Raaz.Core.Encode.Internal

-- | The base16 type.
newtype Base16 = Base16 {unBase16 :: ByteString} deriving Eq

-- Developers note: Internally base16 just stores the bytestring as
-- is. The conversion happens when we do an encode and decode of
-- actual base16.

instance Encodable Base16 where
  toByteString          = hex . unBase16

  fromByteString bs
    | odd (B.length bs) = Nothing
    | badCharacter bs   = Nothing
    | otherwise         = Just $ Base16 $ unsafeFromHex bs
    where badCharacter  = C8.all (not . isHexDigit)

  unsafeFromByteString  = Base16 . unsafeFromHex


instance Show Base16 where
  show = C8.unpack . toByteString

instance IsString Base16 where
  fromString = unsafeFromByteString . fromString


instance Format Base16 where
  encodeByteString = Base16
  {-# INLINE encodeByteString #-}

  decodeFormat     = unBase16
  {-# INLINE decodeFormat #-}

-- TODO: Since the encoding to base16 is usually used for user interaction
-- we can afford to be slower here.
hex :: ByteString -> ByteString
hex  bs = fst $ B.unfoldrN (2 * B.length bs) gen 0
    where gen i | rm == 0   = Just (hexDigit $ top4 w, i+1)
                | otherwise = Just (hexDigit $ bot4 w, i+1)
            where (idx, rm) = quotRem i 2
                  w         = unsafeIndex bs idx

hexDigit :: Word8 -> Word8
hexDigit x | x < 10    = c2w '0' + x
           | otherwise = c2w 'a' + (x - 10)

top4 :: Word8 -> Word8; top4 x  = x `shiftR` 4
bot4 :: Word8 -> Word8; bot4 x  = x  .&. 0x0F


unsafeFromHex :: ByteString -> ByteString
unsafeFromHex bs | odd (B.length bs) = error "base16 encoding is always of even size"
                 | otherwise         = fst $ B.unfoldrN len gen 0
  where len   = B.length bs `quot` 2
        gen i = Just (shiftL w0 4 .|. w1, i + 1)
          where w0 = fromHexWord $ unsafeIndex bs (2 * i)
                w1 = fromHexWord $ unsafeIndex bs (2 * i + 1)
        fromHexWord x
          | c2w '0' <= x && x <= c2w '9' = x - c2w '0'
          | c2w 'a' <= x && x <= c2w 'f' = 10 + (x - c2w 'a')
          | c2w 'A' <= x && x <= c2w 'F' = 10 + (x - c2w 'A')
          | otherwise                    = error "bad base16 character"


-- | Base16 variant of `fromString`. Useful in definition of
-- `IsString` instances as well as in cases where the default
-- `IsString` instance does not parse from a base16 encoding.
fromBase16 :: Encodable a => String -> a
fromBase16 str = unsafeDecode (fromString str :: Base16)

-- | Base16 variant of `show`.
showBase16 :: Encodable a => a -> String
showBase16 a = show (encode a :: Base16)
