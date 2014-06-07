{-

Arithmetic operations for AES

-}

module Raaz.Cipher.Util.GF where

import Data.Bits

import Raaz.Core.Types

mult02 :: Word32BE -> Word32BE
mult02 w = ((w `shiftL` 1) .&. 0xfefefefe) `xor` (((w `shiftR` 7) .&. 0x01010101) * 0x1b)
{-# INLINE mult02 #-}
