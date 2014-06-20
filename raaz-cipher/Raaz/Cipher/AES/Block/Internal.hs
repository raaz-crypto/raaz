{-

This module implements the reference implementation for AES. It is
verbatim translation of the standard and doesn't perform any optimizations

-}
{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE DeriveDataTypeable        #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.Block.Internal
       ( expand128
       , cCompress128
       , hCompress128
       , encrypt128
       , decrypt128
       , expand192
       , cCompress192
       , hCompress192
       , encrypt192
       , decrypt192
       , expand256
       , cCompress256
       , hCompress256
       , encrypt256
       , decrypt256
       , xorState
       , hExpand128, hExpand192, hExpand256
       , cExpand128, cExpand192, cExpand256
       , module Raaz.Cipher.AES.Block.Type
       ) where

import Data.ByteString            (ByteString, pack)
import Data.ByteString.Char8      ()
import Data.ByteString.Unsafe
import Data.Bits
import Data.Word
import Foreign.Storable           (sizeOf, Storable)

import Raaz.Core.Memory
import Raaz.Core.Types
import Raaz.Core.Util.Ptr         (allocaBuffer)

import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.Util.GF


sbox :: Word8 -> Word8
sbox = unsafeIndex sboxArr . fromIntegral
{-# INLINE sbox #-}

sboxArr :: ByteString
sboxArr = pack
  [ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE
  , 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4
  , 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7
  , 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3
  , 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09
  , 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3
  , 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE
  , 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85
  , 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92
  , 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C
  , 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19
  , 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14
  , 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2
  , 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5
  , 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25
  , 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A
  , 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86
  , 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E
  , 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42
  , 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
  ]

invSbox :: Word8 -> Word8
invSbox = unsafeIndex invSboxArr . fromIntegral
{-# INLINE invSbox #-}

invSboxArr :: ByteString
invSboxArr = pack
  [ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81
  , 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E
  , 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23
  , 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66
  , 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72
  , 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65
  , 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46
  , 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A
  , 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA
  , 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91
  , 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6
  , 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8
  , 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F
  , 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2
  , 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8
  , 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F
  , 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93
  , 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB
  , 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6
  , 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
  ]

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
    u0' = (mult02 t0') `xor` (mult02 t1')
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

invSubWord :: (BE Word32) -> (BE Word32)
invSubWord = subWordWith invSbox
{-# INLINE invSubWord #-}

subWord :: (BE Word32) -> (BE Word32)
subWord = subWordWith sbox
{-# INLINE subWord #-}

subWordWith :: (Word8 -> Word8) -> (BE Word32) -> (BE Word32)
subWordWith with w = w0' `xor` w1' `xor` w2' `xor` w3'
  where
    w0 = fromIntegral (w `shiftR` 24)
    w1 = fromIntegral (w `shiftR` 16)
    w2 = fromIntegral (w `shiftR` 8)
    w3 = fromIntegral w
    w3' = fromIntegral $ with w3
    w2' = (fromIntegral $ with w2) `shiftL` 8
    w1' = (fromIntegral $ with w1) `shiftL` 16
    w0' = (fromIntegral $ with w0) `shiftL` 24
{-# INLINE subWordWith #-}

rcon :: Int -> (BE Word32)
rcon 0 = 0x8d000000
rcon 1 = 0x01000000
rcon 2 = 0x02000000
rcon 3 = 0x04000000
rcon 4 = 0x08000000
rcon 5 = 0x10000000
rcon 6 = 0x20000000
rcon 7 = 0x40000000
rcon 8 = 0x80000000
rcon 9 = 0x1b000000
rcon 10 = 0x36000000
rcon 11 = 0x6c000000
rcon 12 = 0xd8000000
rcon 13 = 0xab000000
rcon _    = error "Illegal lookup in rcon"

xorState :: STATE -> STATE -> STATE
xorState = addRoundKey
{-# INLINE xorState #-}

expand :: (BE Word32) -> (BE Word32) -> (BE Word32)
expand w sb = w `xor` ((fromIntegral $ sbox (fromIntegral sb)) `shiftL` 24)
{-# INLINE expand #-}

rotateXor :: (BE Word32) -> (BE Word32)
rotateXor w = w `xor` (w `shiftR` 8) `xor` (w `shiftR` 16) `xor` (w `shiftR` 24)
{-# INLINE rotateXor #-}

expand128 :: KEY128 -> Expanded128
expand128 (KEY128 w0 w1 w2 w3) =
    Expanded128 s00 s01 s02 s03
                s04 s05 s06 s07
                s08 s09 s10
    where
      next :: Int -> STATE -> STATE
      next i  (STATE s0 s1 s2 s3) = fmapState rotateXor $ STATE r0 r1 r2 r3
        where
          r0 = expand s0 s1 `xor` rcon i
          r1 = expand s1 s2
          r2 = expand s2 s3
          r3 = expand s3 s0
      s00 = transpose $ STATE w0 w1 w2 w3
      s01 = next 1 s00
      s02 = next 2 s01
      s03 = next 3 s02
      s04 = next 4 s03
      s05 = next 5 s04
      s06 = next 6 s05
      s07 = next 7 s06
      s08 = next 8 s07
      s09 = next 9 s08
      s10 = next 10 s09

encrypt128 :: STATE -> Expanded128 -> STATE
encrypt128 inp (Expanded128 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10)
  = s10
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey inp k00
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

decrypt128 :: STATE -> Expanded128 -> STATE
decrypt128 inp (Expanded128 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10)
  = s10
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey inp k10
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

expand192 :: KEY192 -> Expanded192
expand192 (KEY192 w0 w1 w2 w3 w4 w5) =
    Expanded192 s00 s01 s02 s03 s04 s05 s06
                s07 s08 s09 s10 s11 s12
    where
      next1 :: Int -> STATE -> STATE -> STATE
      next1 i (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        fmapState rotateXor $ STATE r0 r1 r2 r3
        where
          r0 = expand s0 s5 `xor` rcon i
          r1 = expand s1 s6
          r2 = expand s2 s7
          r3 = expand s3 s4
      next2 :: STATE -> STATE -> STATE
      next2 (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        fmapState shiftXor $ STATE r0 r1 r2 r3
        where
          shiftXor w = w `xor` (w `shiftR` 8)
          r0 = s0 `xor` ((s4 `shiftL` 8) .&. 0x0000ff00)
          r1 = s1 `xor` ((s5 `shiftL` 8) .&. 0x0000ff00)
          r2 = s2 `xor` ((s6 `shiftL` 8) .&. 0x0000ff00)
          r3 = s3 `xor` ((s7 `shiftL` 8) .&. 0x0000ff00)
      getExpanded1 :: STATE -> STATE -> STATE
      getExpanded1 (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        STATE r0 r1 r2 r3
        where
          r0 = (s0 `shiftL` 16) .|. (s4 `shiftR` 16)
          r1 = (s1 `shiftL` 16) .|. (s5 `shiftR` 16)
          r2 = (s2 `shiftL` 16) .|. (s6 `shiftR` 16)
          r3 = (s3 `shiftL` 16) .|. (s7 `shiftR` 16)
      getExpanded2 :: STATE -> STATE -> STATE
      getExpanded2 (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        STATE r0 r1 r2 r3
        where
          r0 = (s0 `shiftL` 16) .|. s4
          r1 = (s1 `shiftL` 16) .|. s5
          r2 = (s2 `shiftL` 16) .|. s6
          r3 = (s3 `shiftL` 16) .|. s7
      t00 = transpose $ STATE w0 w1 w2 w3
      t01 = transpose $ STATE 0  0  w4 w5
      s00 = t00
      t02 = next1 1 t00 t01
      t03 = next2   t01 t02
      s01 = getExpanded1 t01 t02
      s02 = getExpanded2 t02 t03
      t04 = next1 2 t02 t03
      t05 = next2   t03 t04
      s03 = t04
      t06 = next1 3 t04 t05
      t07 = next2   t05 t06
      s04 = getExpanded1 t05 t06
      s05 = getExpanded2 t06 t07
      t08 = next1 4 t06 t07
      t09 = next2   t07 t08
      s06 = t08
      t10 = next1 5 t08 t09
      t11 = next2   t09 t10
      s07 = getExpanded1 t09 t10
      s08 = getExpanded2 t10 t11
      t12 = next1 6 t10 t11
      t13 = next2   t11 t12
      s09 = t12
      t14 = next1 7 t12 t13
      t15 = next2   t13 t14
      s10 = getExpanded1 t13 t14
      s11 = getExpanded2 t14 t15
      s12 = next1 8 t14 t15


encrypt192 :: STATE -> Expanded192 -> STATE
encrypt192 inp (Expanded192 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                            k11 k12) = s12
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey inp k00
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

decrypt192 :: STATE -> Expanded192 -> STATE
decrypt192 inp (Expanded192 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12) = s12
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey inp k12
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

expand256 :: KEY256 -> Expanded256
expand256 (KEY256 w0 w1 w2 w3 w4 w5 w6 w7) =
    Expanded256 s00 s01 s02 s03
                s04 s05 s06 s07
                s08 s09 s10 s11
                s12 s13 s14
    where
      next1 :: Int -> STATE -> STATE -> STATE
      next1 i (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        fmapState rotateXor $ STATE r0 r1 r2 r3
        where
          r0 = expand s0 s5 `xor` rcon i
          r1 = expand s1 s6
          r2 = expand s2 s7
          r3 = expand s3 s4
      next2 :: STATE -> STATE -> STATE
      next2 (STATE s0 s1 s2 s3) (STATE s4 s5 s6 s7) =
        fmapState rotateXor $ STATE r0 r1 r2 r3
        where
          r0 = expand s0 s4
          r1 = expand s1 s5
          r2 = expand s2 s6
          r3 = expand s3 s7
      s00 = transpose $ STATE w0 w1 w2 w3
      s01 = transpose $ STATE w4 w5 w6 w7
      s02 = next1 1 s00 s01
      s03 = next2   s01 s02
      s04 = next1 2 s02 s03
      s05 = next2   s03 s04
      s06 = next1 3 s04 s05
      s07 = next2   s05 s06
      s08 = next1 4 s06 s07
      s09 = next2   s07 s08
      s10 = next1 5 s08 s09
      s11 = next2   s09 s10
      s12 = next1 6 s10 s11
      s13 = next2   s11 s12
      s14 = next1 7 s12 s13

encrypt256 :: STATE -> Expanded256 -> STATE
encrypt256 inp (Expanded256 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12 k13 k14) = s14
    where
      aesRound k = flip addRoundKey k . mixColumns . shiftRows . subBytes
      s00 = addRoundKey inp k00
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

decrypt256 :: STATE -> Expanded256 -> STATE
decrypt256 inp (Expanded256 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                           k11 k12 k13 k14) = s14
    where
      aesRound k =  invMixColumns . flip invAddRoundKey k . invSubBytes . invShiftRows
      s00 = addRoundKey inp k14
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

hExpand128 :: KEY128 -> CryptoCell Expanded128 -> IO ()
hExpand128 k excell = cellStore excell (expand128 k)

hExpand192 :: KEY192 -> CryptoCell Expanded192 -> IO ()
hExpand192 k excell = cellStore excell (expand192 k)

hExpand256 :: KEY256 -> CryptoCell Expanded256 -> IO ()
hExpand256 k excell = cellStore excell (expand256 k)

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: CryptoPtr  -- ^ expanded key
            -> CryptoPtr  -- ^ key
            -> Int        -- ^ Key type
            -> IO ()

cExpansionWith :: (EndianStore k, Storable ek)
               => CryptoCell ek
               -> k
               -> (CryptoPtr -> CryptoPtr -> Int -> IO ())
               -> Int
               -> IO ()
cExpansionWith ek k with i = allocaBuffer szk $ \kptr -> do
  store kptr k
  withCell ek $ expnd kptr
  where
    expnd kptr ekptr = with ekptr kptr i
    szk :: BYTES Int
    szk = BYTES $ sizeOf k
{-# INLINE cExpansionWith #-}

cExpand128 :: KEY128 -> CryptoCell Expanded128 -> IO ()
cExpand128 k excell = cExpansionWith excell k c_expand 0

cExpand192 :: KEY192 -> CryptoCell Expanded192 -> IO ()
cExpand192 k excell = cExpansionWith excell k c_expand 1

cExpand256 :: KEY256 -> CryptoCell Expanded256 -> IO ()
cExpand256 k excell = cExpansionWith excell k c_expand 2

hCompress128 :: Expanded128 -> KEY128
hCompress128 (Expanded128 s0 _ _ _ _ _ _ _ _ _ _) = KEY128 r0 r1 r2 r3
	where (STATE r0 r1 r2 r3) = invTranspose s0

hCompress192 :: Expanded192 -> KEY192
hCompress192 (Expanded192 s0 s1 _ _ _ _ _ _ _ _ _ _ _) =
	KEY192 r0 r1 r2 r3 r4 r5
	where (STATE r0 r1 r2 r3) = invTranspose s0
	      (STATE r4 r5 _ _) = invTranspose s1

hCompress256 :: Expanded256 -> KEY256
hCompress256 (Expanded256 s0 s1 _ _ _ _ _ _ _ _ _ _ _ _ _) =
    KEY256 r0 r1 r2 r3 r4 r5 r6 r7
	where (STATE r0 r1 r2 r3) = invTranspose s0
	      (STATE r4 r5 r6 r7) = invTranspose s1

inverseWord :: (BE Word32) -> (BE Word32)
inverseWord w = w0 `xor` w1 `xor` w2 `xor` w3
    where
      w0 = (w `shiftR` 24) .&. (0x000000ff)
      w1 = (w `shiftR`  8) .&. (0x0000ff00)
      w2 = (w `shiftL`  8) .&. (0x00ff0000)
      w3 = (w `shiftL` 24) .&. (0xff000000)

cCompress128 :: Expanded128 -> KEY128
cCompress128 (Expanded128 s0 _ _ _ _ _ _ _ _ _ _) =
    KEY128 r0 r1 r2 r3
	  where (STATE r0 r1 r2 r3) = invTranspose $ fmapState inverseWord s0

cCompress192 :: Expanded192 -> KEY192
cCompress192 (Expanded192 s0 s1 _ _ _ _ _ _ _ _ _ _ _) =
	KEY192 r0 r1 r2 r3 r4 r5
	where (STATE r0 r1 r2 r3) = invTranspose $ fmapState inverseWord s0
	      (STATE r4 r5 _ _) = invTranspose $ fmapState inverseWord s1

cCompress256 :: Expanded256 -> KEY256
cCompress256 (Expanded256 s0 s1 _ _ _ _ _ _ _ _ _ _ _ _ _) =
    KEY256 r0 r1 r2 r3 r4 r5 r6 r7
	where (STATE r0 r1 r2 r3) = invTranspose $ fmapState inverseWord s0
	      (STATE r4 r5 r6 r7) = invTranspose $ fmapState inverseWord s1
