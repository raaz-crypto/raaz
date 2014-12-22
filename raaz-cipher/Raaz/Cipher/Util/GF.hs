{-

Arithmetic operations for AES

-}

module Raaz.Cipher.Util.GF where

import Data.Bits
import Data.Word

import Raaz.Core.Types

mult02 :: BE Word32 -> BE Word32
mult02 w = ((w `shiftL` 1) .&. 0xfefefefe) `xor` (((w `shiftR` 7) .&. 0x01010101) * 0x1b)
{-# INLINE mult02 #-}
