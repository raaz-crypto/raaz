{-

This module implements the reference implementation for AES. It is
verbatim translation of the standard and doesn't perform any optimizations

-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}
{-# CFILES raaz/cipher/cportable/aes.c  #-}

module Raaz.Cipher.AES.Block.Internal
       ( encrypt128, decrypt128
       , encrypt192, decrypt192
       , encrypt256, decrypt256
       , xorState, incrState

       , module Raaz.Cipher.AES.Block.Type
       ) where


import Data.ByteString            (ByteString)
import Data.ByteString.Char8      ()
import Data.ByteString.Unsafe
import Data.Bits
import Data.Word

import Raaz.Core.Types

import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.Util.GF

sbox :: Word8 -> Word8
sbox = unsafeIndex sboxArr . fromIntegral
{-# INLINE sbox #-}

sboxArr :: ByteString
sboxArr = "\x63\x7C\x77\x7B\xF2\x6B\x6F\xC5\x30\x01\x67\x2B\xFE\
          \\xD7\xAB\x76\xCA\x82\xC9\x7D\xFA\x59\x47\xF0\xAD\xD4\
          \\xA2\xAF\x9C\xA4\x72\xC0\xB7\xFD\x93\x26\x36\x3F\xF7\
          \\xCC\x34\xA5\xE5\xF1\x71\xD8\x31\x15\x04\xC7\x23\xC3\
          \\x18\x96\x05\x9A\x07\x12\x80\xE2\xEB\x27\xB2\x75\x09\
          \\x83\x2C\x1A\x1B\x6E\x5A\xA0\x52\x3B\xD6\xB3\x29\xE3\
          \\x2F\x84\x53\xD1\x00\xED\x20\xFC\xB1\x5B\x6A\xCB\xBE\
          \\x39\x4A\x4C\x58\xCF\xD0\xEF\xAA\xFB\x43\x4D\x33\x85\
          \\x45\xF9\x02\x7F\x50\x3C\x9F\xA8\x51\xA3\x40\x8F\x92\
          \\x9D\x38\xF5\xBC\xB6\xDA\x21\x10\xFF\xF3\xD2\xCD\x0C\
          \\x13\xEC\x5F\x97\x44\x17\xC4\xA7\x7E\x3D\x64\x5D\x19\
          \\x73\x60\x81\x4F\xDC\x22\x2A\x90\x88\x46\xEE\xB8\x14\
          \\xDE\x5E\x0B\xDB\xE0\x32\x3A\x0A\x49\x06\x24\x5C\xC2\
          \\xD3\xAC\x62\x91\x95\xE4\x79\xE7\xC8\x37\x6D\x8D\xD5\
          \\x4E\xA9\x6C\x56\xF4\xEA\x65\x7A\xAE\x08\xBA\x78\x25\
          \\x2E\x1C\xA6\xB4\xC6\xE8\xDD\x74\x1F\x4B\xBD\x8B\x8A\
          \\x70\x3E\xB5\x66\x48\x03\xF6\x0E\x61\x35\x57\xB9\x86\
          \\xC1\x1D\x9E\xE1\xF8\x98\x11\x69\xD9\x8E\x94\x9B\x1E\
          \\x87\xE9\xCE\x55\x28\xDF\x8C\xA1\x89\x0D\xBF\xE6\x42\
          \\x68\x41\x99\x2D\x0F\xB0\x54\xBB\x16"

invSbox :: Word8 -> Word8
invSbox = unsafeIndex invSboxArr . fromIntegral
{-# INLINE invSbox #-}

invSboxArr :: ByteString
invSboxArr = "\x52\x09\x6A\xD5\x30\x36\xA5\x38\xBF\x40\xA3\x9E\x81\
             \\xF3\xD7\xFB\x7C\xE3\x39\x82\x9B\x2F\xFF\x87\x34\x8E\
             \\x43\x44\xC4\xDE\xE9\xCB\x54\x7B\x94\x32\xA6\xC2\x23\
             \\x3D\xEE\x4C\x95\x0B\x42\xFA\xC3\x4E\x08\x2E\xA1\x66\
             \\x28\xD9\x24\xB2\x76\x5B\xA2\x49\x6D\x8B\xD1\x25\x72\
             \\xF8\xF6\x64\x86\x68\x98\x16\xD4\xA4\x5C\xCC\x5D\x65\
             \\xB6\x92\x6C\x70\x48\x50\xFD\xED\xB9\xDA\x5E\x15\x46\
             \\x57\xA7\x8D\x9D\x84\x90\xD8\xAB\x00\x8C\xBC\xD3\x0A\
             \\xF7\xE4\x58\x05\xB8\xB3\x45\x06\xD0\x2C\x1E\x8F\xCA\
             \\x3F\x0F\x02\xC1\xAF\xBD\x03\x01\x13\x8A\x6B\x3A\x91\
             \\x11\x41\x4F\x67\xDC\xEA\x97\xF2\xCF\xCE\xF0\xB4\xE6\
             \\x73\x96\xAC\x74\x22\xE7\xAD\x35\x85\xE2\xF9\x37\xE8\
             \\x1C\x75\xDF\x6E\x47\xF1\x1A\x71\x1D\x29\xC5\x89\x6F\
             \\xB7\x62\x0E\xAA\x18\xBE\x1B\xFC\x56\x3E\x4B\xC6\xD2\
             \\x79\x20\x9A\xDB\xC0\xFE\x78\xCD\x5A\xF4\x1F\xDD\xA8\
             \\x33\x88\x07\xC7\x31\xB1\x12\x10\x59\x27\x80\xEC\x5F\
             \\x60\x51\x7F\xA9\x19\xB5\x4A\x0D\x2D\xE5\x7A\x9F\x93\
             \\xC9\x9C\xEF\xA0\xE0\x3B\x4D\xAE\x2A\xF5\xB0\xC8\xEB\
             \\xBB\x3C\x83\x53\x99\x61\x17\x2B\x04\x7E\xBA\x77\xD6\
             \\x26\xE1\x69\x14\x63\x55\x21\x0C\x7D"


subBytes :: STATE -> STATE
subBytes (STATE s0 s1 s2 s3) = STATE (subWord s0)
                                     (subWord s1)
                                     (subWord s2)
                                     (subWord s3)
{-# INLINE subBytes #-}

invSubBytes :: STATE -> STATE
invSubBytes (STATE s0 s1 s2 s3) = STATE (invSubWord s0)
                                        (invSubWord s1)
                                        (invSubWord s2)
                                        (invSubWord s3)
{-# INLINE invSubBytes #-}


shiftRows :: STATE -> STATE
shiftRows (STATE s0 s1 s2 s3) = STATE s0
                                      (s1 `rotateL` 8)
                                      (s2 `rotateL` 16)
                                      (s3 `rotateL` 24)
{-# INLINE shiftRows #-}

invShiftRows :: STATE -> STATE
invShiftRows (STATE s0 s1 s2 s3) = STATE s0
                                      (s1 `rotateL` 24)
                                      (s2 `rotateL` 16)
                                      (s3 `rotateL` 8)
{-# INLINE invShiftRows #-}

mixColumns :: STATE -> STATE
mixColumns state@(STATE s0 s1 s2 s3) = STATE r0 r1 r2 r3
  where
    r0' = s1 `xor` s2 `xor` s3
    r1' = s0 `xor` s2 `xor` s3
    r2' = s0 `xor` s1 `xor` s3
    r3' = s0 `xor` s1 `xor` s2
    (STATE s0' s1' s2' s3') = fmapState mult02 state
    r0 = r0' `xor` s0' `xor` s1'
    r1 = r1' `xor` s1' `xor` s2'
    r2 = r2' `xor` s2' `xor` s3'
    r3 = r3' `xor` s0' `xor` s3'
{-# INLINE mixColumns #-}

invMixColumns :: STATE -> STATE
invMixColumns state@(STATE s0 s1 s2 s3) = STATE u0 u1 u2 u3
  where
    r0' = s1 `xor` s2 `xor` s3
    r1' = s0 `xor` s2 `xor` s3
    r2' = s0 `xor` s1 `xor` s3
    r3' = s0 `xor` s1 `xor` s2
    (STATE s0' s1' s2' s3') = fmapState mult02 state
    r0 = r0' `xor` s0' `xor` s1'
    r1 = r1' `xor` s1' `xor` s2'
    r2 = r2' `xor` s2' `xor` s3'
    r3 = r3' `xor` s0' `xor` s3'
    t0' = mult02 $ s0' `xor` s2'
    t1' = mult02 $ s1' `xor` s3'
    t0 =  r0 `xor` t0'
    t1 =  r1 `xor` t1'
    t2 =  r2 `xor` t0'
    t3 =  r3 `xor` t1'
    u0' = mult02 t0' `xor` mult02 t1'
    u0 = t0 `xor` u0'
    u1 = t1 `xor` u0'
    u2 = t2 `xor` u0'
    u3 = t3 `xor` u0'
{-# INLINE invMixColumns #-}

addRoundKey :: STATE -> STATE -> STATE
addRoundKey (STATE s0 s1 s2 s3)
            (STATE k0 k1 k2 k3) =
  STATE (s0 `xor` k0) (s1 `xor` k1) (s2 `xor` k2) (s3 `xor` k3)
{-# INLINE addRoundKey #-}

invAddRoundKey :: STATE -> STATE -> STATE
invAddRoundKey = addRoundKey
{-# INLINE invAddRoundKey #-}

invSubWord :: BE Word32 -> BE Word32
invSubWord = subWordWith invSbox
{-# INLINE invSubWord #-}

subWord :: BE Word32 -> BE Word32
subWord = subWordWith sbox
{-# INLINE subWord #-}

subWordWith :: (Word8 -> Word8) -> BE Word32 -> BE Word32
subWordWith with w = w0' `xor` w1' `xor` w2' `xor` w3'
  where
    w0 = fromIntegral (w `shiftR` 24)
    w1 = fromIntegral (w `shiftR` 16)
    w2 = fromIntegral (w `shiftR` 8)
    w3 = fromIntegral w
    w3' = fromIntegral $ with w3
    w2' = fromIntegral (with w2) `shiftL` 8
    w1' = fromIntegral (with w1) `shiftL` 16
    w0' = fromIntegral (with w0) `shiftL` 24
{-# INLINE subWordWith #-}

xorState :: STATE -> STATE -> STATE
xorState = addRoundKey
{-# INLINE xorState #-}

encrypt128 :: STATE -> Expanded KEY128 -> STATE
encrypt128 inp (Expanded128 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10)
  = invTranspose s10
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey (transpose inp) k00
      s01 = aesRound k01 s00
      s02 = aesRound k02 s01
      s03 = aesRound k03 s02
      s04 = aesRound k04 s03
      s05 = aesRound k05 s04
      s06 = aesRound k06 s05
      s07 = aesRound k07 s06
      s08 = aesRound k08 s07
      s09 = aesRound k09 s08
      s10 = addRoundKey (shiftRows $ subBytes s09) k10

decrypt128 :: STATE -> Expanded KEY128 -> STATE
decrypt128 inp (Expanded128 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10)
  = invTranspose s10
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey (transpose inp) k10
      s01 = aesRound k09 s00
      s02 = aesRound k08 s01
      s03 = aesRound k07 s02
      s04 = aesRound k06 s03
      s05 = aesRound k05 s04
      s06 = aesRound k04 s05
      s07 = aesRound k03 s06
      s08 = aesRound k02 s07
      s09 = aesRound k01 s08
      s10 = invAddRoundKey (invSubBytes $ invShiftRows s09) k00

encrypt192 :: STATE -> Expanded KEY192 -> STATE
encrypt192 inp (Expanded192 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                            k11 k12) = invTranspose s12
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey (transpose inp) k00
      s01 = aesRound k01 s00
      s02 = aesRound k02 s01
      s03 = aesRound k03 s02
      s04 = aesRound k04 s03
      s05 = aesRound k05 s04
      s06 = aesRound k06 s05
      s07 = aesRound k07 s06
      s08 = aesRound k08 s07
      s09 = aesRound k09 s08
      s10 = aesRound k10 s09
      s11 = aesRound k11 s10
      s12 = flip addRoundKey k12 . shiftRows $ subBytes s11

decrypt192 :: STATE -> Expanded KEY192 -> STATE
decrypt192 inp (Expanded192 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12) = invTranspose s12
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey (transpose inp) k12
      s01 = aesRound k11 s00
      s02 = aesRound k10 s01
      s03 = aesRound k09 s02
      s04 = aesRound k08 s03
      s05 = aesRound k07 s04
      s06 = aesRound k06 s05
      s07 = aesRound k05 s06
      s08 = aesRound k04 s07
      s09 = aesRound k03 s08
      s10 = aesRound k02 s09
      s11 = aesRound k01 s10
      s12 = invAddRoundKey (invSubBytes $ invShiftRows s11) k00

encrypt256 :: STATE -> Expanded KEY256 -> STATE
encrypt256 inp (Expanded256 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12 k13 k14) = invTranspose s14
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey (transpose inp) k00
      s01 = aesRound k01 s00
      s02 = aesRound k02 s01
      s03 = aesRound k03 s02
      s04 = aesRound k04 s03
      s05 = aesRound k05 s04
      s06 = aesRound k06 s05
      s07 = aesRound k07 s06
      s08 = aesRound k08 s07
      s09 = aesRound k09 s08
      s10 = aesRound k10 s09
      s11 = aesRound k11 s10
      s12 = aesRound k12 s11
      s13 = aesRound k13 s12
      s14 = flip addRoundKey k14 . shiftRows $ subBytes s13

decrypt256 :: STATE -> Expanded KEY256 -> STATE
decrypt256 inp (Expanded256 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12 k13 k14) = invTranspose s14
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey (transpose inp) k14
      s01 = aesRound k13 s00
      s02 = aesRound k12 s01
      s03 = aesRound k11 s02
      s04 = aesRound k10 s03
      s05 = aesRound k09 s04
      s06 = aesRound k08 s05
      s07 = aesRound k07 s06
      s08 = aesRound k06 s07
      s09 = aesRound k05 s08
      s10 = aesRound k04 s09
      s11 = aesRound k03 s10
      s12 = aesRound k02 s11
      s13 = aesRound k01 s12
      s14 = invAddRoundKey (invSubBytes $ invShiftRows s13) k00


-- | Incrments the STATE considering it to be a byte string. It is
-- sligthly different because of transposing of data during load and
-- store. Used in AES CTR mode.
incrState :: STATE -> STATE
incrState = incr
  where
    incr (STATE w0 w1 w2 w3) = STATE r0 r1 r2 r3
      where
        ifincr prev this = if prev == 0 then this + 1 else this
        r3 = w3 + 1
        r2 = ifincr r3 w2
        r1 = ifincr r2 w1
        r0 = ifincr r1 w0

-- | Maps a function over `STATE`.
fmapState :: (BE Word32 -> BE Word32) -> STATE -> STATE
fmapState f (STATE s0 s1 s2 s3) = STATE (f s0) (f s1) (f s2) (f s3)

-- | Constructs a (BE Word32) from Least significan 8 bits of given 4 words
constructWord32BE :: BE Word32 -> BE Word32 -> BE Word32 -> BE Word32 -> BE Word32
constructWord32BE w0 w1 w2 w3 = r3 `xor` r2 `xor` r1 `xor` r0
  where
    mask w = w .&. 0x000000FF
    r3 = mask w3
    r2 = mask w2 `shiftL` 8
    r1 = mask w1 `shiftL` 16
    r0 = mask w0 `shiftL` 24

-- | Transpose of the STATE
transpose :: STATE -> STATE
transpose (STATE w0 w1 w2 w3) =
           STATE (constructWord32BE s00 s01 s02 s03)
                 (constructWord32BE s10 s11 s12 s13)
                 (constructWord32BE s20 s21 s22 s23)
                 (constructWord32BE w0 w1 w2 w3)
  where
    s20 = w0 `shiftR` 8
    s21 = w1 `shiftR` 8
    s22 = w2 `shiftR` 8
    s23 = w3 `shiftR` 8
    s10 = w0 `shiftR` 16
    s11 = w1 `shiftR` 16
    s12 = w2 `shiftR` 16
    s13 = w3 `shiftR` 16
    s00 = w0 `shiftR` 24
    s01 = w1 `shiftR` 24
    s02 = w2 `shiftR` 24
    s03 = w3 `shiftR` 24
{-# INLINE transpose #-}

-- | Reverse of Transpose of STATE
invTranspose :: STATE -> STATE
invTranspose (STATE w0 w1 w2 w3) =
           STATE (constructWord32BE s00 s01 s02 s03)
                 (constructWord32BE s10 s11 s12 s13)
                 (constructWord32BE s20 s21 s22 s23)
                 (constructWord32BE s30 s31 s32 s33)
  where
    s00 = w0 `shiftR` 24
    s10 = w0 `shiftR` 16
    s20 = w0 `shiftR` 8
    s30 = w0
    s01 = w1 `shiftR` 24
    s11 = w1 `shiftR` 16
    s21 = w1 `shiftR` 8
    s31 = w1
    s02 = w2 `shiftR` 24
    s12 = w2 `shiftR` 16
    s22 = w2 `shiftR` 8
    s32 = w2
    s03 = w3 `shiftR` 24
    s13 = w3 `shiftR` 16
    s23 = w3 `shiftR` 8
    s33 = w3
