{-

This module implements the reference implementation for AES. It is
verbatim translation of the standard and doesn't perform any optimizations

-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}
{-# CFILES raaz/cipher/cportable/aes.c  #-}

module Raaz.Cipher.AES.Block.Internal
       ( encrypt128, decrypt128
       , encrypt192, decrypt192
       , encrypt256, decrypt256
       , xorState, incrState
       , AESIVMem(..), AESKEYMem(..)
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

xorState :: STATE -> STATE -> STATE
xorState = addRoundKey
{-# INLINE xorState #-}

encrypt128 :: STATE -> Expanded128 -> STATE
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

decrypt128 :: STATE -> Expanded128 -> STATE
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

encrypt192 :: STATE -> Expanded192 -> STATE
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

decrypt192 :: STATE -> Expanded192 -> STATE
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

encrypt256 :: STATE -> Expanded256 -> STATE
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

decrypt256 :: STATE -> Expanded256 -> STATE
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

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: CryptoPtr  -- ^ expanded key
            -> CryptoPtr  -- ^ key
            -> Int        -- ^ Key type
            -> IO ()

-- | SECURITY LOOPHOLE TO FIX. Memory allocated through `allocaBuffer`
-- is not a secureMemory and would not be scrubbed. The alternative to
-- fix this is to change the context to a Memory containing Key
-- instead of pure Key (similar for IV) and that memory should be
-- passed while interfacing with C code.
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
fmapState :: ((BE Word32) -> (BE Word32)) -> STATE -> STATE
fmapState f (STATE s0 s1 s2 s3) = STATE (f s0) (f s1) (f s2) (f s3)

-- | Constructs a (BE Word32) from Least significan 8 bits of given 4 words
constructWord32BE :: (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
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

-- | Memory to store expanded key. Note that it uses the C expand
-- function for key expansion.
newtype AESKEYMem key = AESKEYMem (CryptoCell key) deriving Memory

instance InitializableMemory (AESKEYMem Expanded128) where
  type IV (AESKEYMem Expanded128) = KEY128

  initializeMemory (AESKEYMem cell) k = cExpand128 k cell

instance InitializableMemory (AESKEYMem Expanded192) where
  type IV (AESKEYMem Expanded192) = KEY192

  initializeMemory (AESKEYMem cell) k = cExpand192 k cell

instance InitializableMemory (AESKEYMem Expanded256) where
  type IV (AESKEYMem Expanded256) = KEY256

  initializeMemory (AESKEYMem cell) k = cExpand256 k cell

-- | Memory to store IV (which is just STATE)
newtype AESIVMem = AESIVMem (CryptoCell STATE) deriving Memory

instance InitializableMemory AESIVMem where
  type IV AESIVMem = STATE

  initializeMemory (AESIVMem cell) s = withCell cell (flip store s)
