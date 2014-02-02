{-

Arithmetic operations for AES

-}

module Raaz.Cipher.Util.GF where

import Data.Bits
import Data.List (foldl')
import Data.Word


xpower :: Int -> Word8 -> Word8
xpower n w = foldl' (const . xtime02) w [1..n]
{-# INLINE xpower #-}

xtime02 :: Word8 -> Word8
xtime02 x = if x .&. 0x80 == 0 then a else a `xor` 0x1b
  where
    a = x `shiftL` 1
{-# INLINE xtime02 #-}

xtime04 :: Word8 -> Word8
xtime04 = xtime02 . xtime02
{-# INLINE xtime04 #-}

xtime08 :: Word8 -> Word8
xtime08 = xtime02 . xtime02 . xtime02
{-# INLINE xtime08 #-}

xtime03 :: Word8 -> Word8
xtime03 x = x `xor` xtime02 x
{-# INLINE xtime03 #-}

xtime0b :: Word8 -> Word8
xtime0b x = x `xor` xtime02 (x `xor` xtime04 x)
{-# INLINE xtime0b #-}

xtime0d :: Word8 -> Word8
xtime0d x = x `xor` xtime04 (x `xor` xtime02 x)
{-# INLINE xtime0d #-}

xtime09 :: Word8 -> Word8
xtime09 x = x `xor` xtime08 x
{-# INLINE xtime09 #-}

xtime0e :: Word8 -> Word8
xtime0e x = xtime02 (x `xor` xtime02 (x `xor` xtime02 x))
{-# INLINE xtime0e #-}
