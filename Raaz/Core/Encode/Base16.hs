-- | Base 16 or hexadecimal encoding of objects.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Encode.Base16( Base16 ) where

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


instance Show Base16 where
  show = C8.unpack . hex . unBase16

instance IsString Base16 where
  fromString = Base16 . unsafeFromHex . fromString


instance Format Base16 where
  encodeByteString = Base16
  {-# INLINE encodeByteString #-}

  decodeFormat     = unBase16
  {-# INLINE decodeFormat #-}

-- TODO: Since the encoding to base16 is usually used for user interaction
-- we can afford to be slower here.

hexDigit :: Word8 -> Word8
hexDigit x | x < 10    = c2w '0' + x
           | otherwise = c2w 'a' + (x - 10)

top4 :: Word8 -> Word8; top4 x  = x `shiftR` 4
bot4 :: Word8 -> Word8; bot4 x  = x  .&. 0x0F

-- | Converts to hexadecimal.
hex :: ByteString -> ByteString
hex bs = fst $ B.unfoldrN (2 * B.length bs) gen 0
  where gen i | rm == 0   = Just (hexDigit $ top4 w, i+1)
              | otherwise = Just (hexDigit $ bot4 w, i+1)
          where (idx, rm) = quotRem i 2
                w         = unsafeIndex bs idx

{--

-- This is potentially faster but unsafe version of hex.converts
bytestring to hexadecimal representation.

hexFast :: ByteString -> ByteString
hexFast bs = unsafeCreate (2 * n) filler
  where (fptr, offset, n)      = toForeignPtr bs

        filler ptr = withForeignPtr fptr $
             \ bsPtr -> putBS (bsPtr `plusPtr` offset) 0 ptr

        putBS bsPtr i ptr
              | i < n     = do x <- peek bsPtr
                               put ptr x
                               putBS bsNewPtr (i+1) ptrNew
              | otherwise = return ()
          where bsNewPtr = bsPtr `plusPtr` 1
                ptrNew   = ptr `plusPtr`   2
        put ptr x = do poke ptr0 $ hexDigit $ top4 x
                       poke ptr1 $ hexDigit $ bot4 x
            where ptr0 = ptr
                  ptr1 = ptr `plusPtr` 1

--}


-- | Converts hexadecimal bytestring to binary assuming that the input
-- bytestring is hexadecimal only.

unsafeFromHex :: ByteString -> ByteString
unsafeFromHex bs | odd (B.length bs) = error "base16 encoding is always of even size"
                 | otherwise         = fst $ B.unfoldrN len gen 0
  where len = B.length bs `quot` 2
        gen i = Just (shiftL w0 4 .|. w1, i + 1)
          where w0 = fromHexWord $ unsafeIndex bs (2 * i)
                w1 = fromHexWord $ unsafeIndex bs (2 * i + 1)
        fromHexWord x
          | isDigit x          = x - c2w '0'
          | between 'a' 'f' x  = 10 + (x - c2w 'a')
          | between 'A' 'F' x  = 10 + (x - c2w 'A')
          | otherwise          = error "bad base16 character"


{--

-- Faster but dangerous version


unsafeFromHex :: ByteString -> ByteString
unsafeFromHex bs = unsafeCreate nOutput filler
  where (fptr, offset, n)      = toForeignPtr bs

        nOutput    = n `quot` 2

        filler ptr = withForeignPtr fptr $
             \ bsPtr -> putBS (bsPtr `plusPtr` offset) 0 ptr

        putBS bsPtr i ptr
              | i < nOutput = do x <- peek  bsPtr
                                 y <- peek (bsPtr `plusPtr` 1)
                                 put ptr x y
                                 putBS bsNewPtr (i+1) ptrNew
              | otherwise = return ()
          where bsNewPtr = bsPtr `plusPtr` 2
                ptrNew   = ptr   `plusPtr` 1

        put ptr x y = poke ptr binaryWord
          where binaryWord = (fromHexWord x `shiftL` 4) .|.
                             fromHexWord y

--}
