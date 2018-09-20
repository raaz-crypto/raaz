-- | Base 64 encoding of objects.
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Encode.Base64( Base64 ) where

import Data.Char
import Data.Bits
import Data.String

import Data.ByteString as B
import Data.ByteString.Char8 as C8
import Data.ByteString.Internal (c2w, w2c)

import Data.ByteString.Unsafe(unsafeIndex)

#if !MIN_VERSION_base(4,8,0)
import Data.Monoid  -- Import only when base < 4.8.0
#endif

#if !MIN_VERSION_base(4,11,0)
import Data.Semigroup
#endif

import Data.Word
import Raaz.Core.Encode.Internal


-- | The type corresponding to the standard padded base-64 binary
-- encoding.
newtype Base64 = Base64 {unBase64 :: ByteString} deriving (Eq, Semigroup, Monoid)

-- Developers note: Internally base16 just stores the bytestring as
-- is. The conversion happens when we do an encode and decode of
-- actual base16.

instance Encodable Base64 where
  toByteString          = toB64 . unBase64

  fromByteString bs
    | B.null bs                = Just $ Base64 B.empty
    | B.length bs `rem` 4 /= 0 = Nothing
    | okeyPad                  = Just $ Base64 $ unsafeFromB64 bs
    | otherwise                = Nothing
    where padPart     = C8.dropWhile isB64Char bs
          okeyPad     = padPart == C8.empty || padPart == C8.singleton '=' || padPart == C8.pack "=="
          isB64Char c = isAlpha c || isDigit c || c == '+' || c == '/'


  unsafeFromByteString bs | B.null bs = Base64 B.empty
                          | otherwise = Base64 $ unsafeFromB64 bs


instance Show Base64 where
  show = C8.unpack . toByteString

-- | Ignores spaces and newlines.
instance IsString Base64 where
  fromString = unsafeFromByteString . C8.filter (not . isSpace) . fromString

instance Format Base64 where
  encodeByteString = Base64
  {-# INLINE encodeByteString #-}

  decodeFormat     = unBase64
  {-# INLINE decodeFormat #-}



------------- Base 64 encoding -------------------------

-- NOTE: The topN functions ensure that the top N bits of a word are present
-- in the least N significant bits. The botN ensures that there

top6 :: Word8 -> Word8; bot2 :: Word8 -> Word8
top4 :: Word8 -> Word8; bot4 :: Word8 -> Word8
top2 :: Word8 -> Word8; bot6 :: Word8 -> Word8

top6 w = w `shiftR` 2; bot2 w = w .&. 0x03
top4 w = w `shiftR` 4; bot4 w = w .&. 0x0F
top2 w = w `shiftR` 6; bot6 w = w .&. 0x3F

--------------- Combining bytes -----------------------------------

byte0 :: Word8 -> Word8
byte1 :: Word8 -> Word8 -> Word8
byte2 :: Word8 -> Word8 -> Word8
byte3 :: Word8 -> Word8
pad   :: Word8


byte0     = b64 . top6
byte1 t p = b64 $ shiftL (bot2 p) 4 .|. top4 t
byte2 t p = b64 $ shiftL (bot4 p) 2 .|. top2 t
byte3     = b64 . bot6
pad       = c2w '='

-- | Encoding word.
b64 :: Word8 -> Word8
b64 w | 0  <= w  && w <= 25 = c2w 'A' + w
      | 26 <= w  && w <= 51 = c2w 'a' + w - 26
      | 52 <= w  && w <= 61 = c2w '0' + w - 52
      | w == 62             = c2w '+'
      | w == 63             = c2w '/'
      | otherwise           = error "oops: b64"


unB64 :: Word8 -> Word8
unB64 w | c2w 'A' <= w && w <= c2w 'Z' = w - c2w 'A'
        | c2w 'a' <= w && w <= c2w 'z' = w - c2w 'a' + 26
        | c2w '0' <= w && w <= c2w '9' = w - c2w '0' + 52
        | w == c2w '+'                 = 62
        | w == c2w '/'                 = 63
        | otherwise                    = error $ "oops unB64:" ++ [w2c w]




-- Since the encoding to base16 is usually used for user interaction
-- we can afford to be slower here.

-- TODO (Liquid Haskell)
--
{--@ toB64 :: ByteString -> { bs : ByteString | (bslen bs) mod 4 == 0 @-}
--
toB64 :: ByteString -> ByteString
toB64 bs = fst (B.unfoldrN (4*n) gen 0) <> padding
    where gen i    = Just (byte i, i + 1)
          at blk i = unsafeIndex bs $ 3 * blk + i

          byte i = case r of
            0 -> byte0          $ at q 0
            1 -> byte1 (at q 1) $ at q 0
            2 -> byte2 (at q 2) $ at q 1
            3 -> byte3          $ at q 2
            _ -> error "base64 bad index"
            where (q, r) = quotRem i 4

          (n,p) = B.length bs `quotRem` 3

          padding = case p of
            0 -> mempty
            1 -> B.pack [ byte0   $ at n 0
                        , byte1 0 $ at n 0
                        , pad, pad
                        ]
            2 -> B.pack [ byte0          $ at n 0
                        , byte1 (at n 1) $ at n 0
                        , byte2 0        $ at n 1
                        , pad
                        ]
            _ -> error "base64 pad bad index"

-- Notes: Merge is used to convert from base64 digits, which are
-- words of 6-bits.
merg0 :: Word8 -> Word8 -> Word8
merg1 :: Word8 -> Word8 -> Word8
merg2 :: Word8 -> Word8 -> Word8
merg0 a b = (unB64 a `shiftL` 2) .|. top4 (unB64 b)
merg1 a b = (unB64 a `shiftL` 4) .|. top6 (unB64 b)
merg2 a b = (unB64 a `shiftL` 6) .|. unB64 b


unsafeFromB64 :: ByteString -> ByteString
unsafeFromB64 bs = fst (B.unfoldrN (3*n) gen 0) <> unPad
  where n         = B.length bs `quot` 4 - 1
        gen i     = Just (byte i, i + 1)
        at blk i  = unsafeIndex bs $ 4 * blk + i

        byte i    = case r of
          0 -> merg0 (at q 0) $ at q 1
          1 -> merg1 (at q 1) $ at q 2
          2 -> merg2 (at q 2) $ at q 3
          _ -> error "base64 bad index"
          where (q, r) = quotRem i 3

        unPad
          | at n 2 == c2w '=' = B.singleton $ merg0 (at n 0) $ at n 1
          | at n 3 == c2w '=' = B.pack [ merg0 (at n 0) $ at n 1
                                       , merg1 (at n 1) $ at n 2
                                       ]
          | otherwise         = B.pack [ merg0 (at n 0) $ at n 1
                                       , merg1 (at n 1) $ at n 2
                                       , merg2 (at n 2) $ at n 3
                                       ]
