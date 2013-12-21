{-

This module implements the reference implementation for AES. It is
verbatim translation of the standard and doesn't perform any optimizations

-}
{-# LANGUAGE TypeFamilies          #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module Raaz.Cipher.AES.Ref.Internal
       ( expand128
       , encrypt128
       , decrypt128
       , expand192
       , encrypt192
       , decrypt192
       , expand256
       , encrypt256
       , decrypt256
       , xorState
       ) where

import Data.Bits
import Data.Word


import Raaz.Cipher.AES.Ref.Type
import Raaz.Cipher.Util.GF


sbox :: Word8 -> Word8
sbox 0x00 = 0x63
sbox 0x01 = 0x7C
sbox 0x02 = 0x77
sbox 0x03 = 0x7B
sbox 0x04 = 0xF2
sbox 0x05 = 0x6B
sbox 0x06 = 0x6F
sbox 0x07 = 0xC5
sbox 0x08 = 0x30
sbox 0x09 = 0x01
sbox 0x0a = 0x67
sbox 0x0b = 0x2B
sbox 0x0c = 0xFE
sbox 0x0d = 0xD7
sbox 0x0e = 0xAB
sbox 0x0f = 0x76

sbox 0x10 = 0xCA
sbox 0x11 = 0x82
sbox 0x12 = 0xC9
sbox 0x13 = 0x7D
sbox 0x14 = 0xFA
sbox 0x15 = 0x59
sbox 0x16 = 0x47
sbox 0x17 = 0xF0
sbox 0x18 = 0xAD
sbox 0x19 = 0xD4
sbox 0x1a = 0xA2
sbox 0x1b = 0xAF
sbox 0x1c = 0x9C
sbox 0x1d = 0xA4
sbox 0x1e = 0x72
sbox 0x1f = 0xC0

sbox 0x20 = 0xB7
sbox 0x21 = 0xFD
sbox 0x22 = 0x93
sbox 0x23 = 0x26
sbox 0x24 = 0x36
sbox 0x25 = 0x3F
sbox 0x26 = 0xF7
sbox 0x27 = 0xCC
sbox 0x28 = 0x34
sbox 0x29 = 0xA5
sbox 0x2a = 0xE5
sbox 0x2b = 0xF1
sbox 0x2c = 0x71
sbox 0x2d = 0xD8
sbox 0x2e = 0x31
sbox 0x2f = 0x15

sbox 0x30 = 0x04
sbox 0x31 = 0xC7
sbox 0x32 = 0x23
sbox 0x33 = 0xC3
sbox 0x34 = 0x18
sbox 0x35 = 0x96
sbox 0x36 = 0x05
sbox 0x37 = 0x9A
sbox 0x38 = 0x07
sbox 0x39 = 0x12
sbox 0x3a = 0x80
sbox 0x3b = 0xE2
sbox 0x3c = 0xEB
sbox 0x3d = 0x27
sbox 0x3e = 0xB2
sbox 0x3f = 0x75

sbox 0x40 = 0x09
sbox 0x41 = 0x83
sbox 0x42 = 0x2C
sbox 0x43 = 0x1A
sbox 0x44 = 0x1B
sbox 0x45 = 0x6E
sbox 0x46 = 0x5A
sbox 0x47 = 0xA0
sbox 0x48 = 0x52
sbox 0x49 = 0x3B
sbox 0x4a = 0xD6
sbox 0x4b = 0xB3
sbox 0x4c = 0x29
sbox 0x4d = 0xE3
sbox 0x4e = 0x2F
sbox 0x4f = 0x84

sbox 0x50 = 0x53
sbox 0x51 = 0xD1
sbox 0x52 = 0x00
sbox 0x53 = 0xED
sbox 0x54 = 0x20
sbox 0x55 = 0xFC
sbox 0x56 = 0xB1
sbox 0x57 = 0x5B
sbox 0x58 = 0x6A
sbox 0x59 = 0xCB
sbox 0x5a = 0xBE
sbox 0x5b = 0x39
sbox 0x5c = 0x4A
sbox 0x5d = 0x4C
sbox 0x5e = 0x58
sbox 0x5f = 0xCF

sbox 0x60 = 0xD0
sbox 0x61 = 0xEF
sbox 0x62 = 0xAA
sbox 0x63 = 0xFB
sbox 0x64 = 0x43
sbox 0x65 = 0x4D
sbox 0x66 = 0x33
sbox 0x67 = 0x85
sbox 0x68 = 0x45
sbox 0x69 = 0xF9
sbox 0x6a = 0x02
sbox 0x6b = 0x7F
sbox 0x6c = 0x50
sbox 0x6d = 0x3C
sbox 0x6e = 0x9F
sbox 0x6f = 0xA8

sbox 0x70 = 0x51
sbox 0x71 = 0xA3
sbox 0x72 = 0x40
sbox 0x73 = 0x8F
sbox 0x74 = 0x92
sbox 0x75 = 0x9D
sbox 0x76 = 0x38
sbox 0x77 = 0xF5
sbox 0x78 = 0xBC
sbox 0x79 = 0xB6
sbox 0x7a = 0xDA
sbox 0x7b = 0x21
sbox 0x7c = 0x10
sbox 0x7d = 0xFF
sbox 0x7e = 0xF3
sbox 0x7f = 0xD2

sbox 0x80 = 0xCD
sbox 0x81 = 0x0C
sbox 0x82 = 0x13
sbox 0x83 = 0xEC
sbox 0x84 = 0x5F
sbox 0x85 = 0x97
sbox 0x86 = 0x44
sbox 0x87 = 0x17
sbox 0x88 = 0xC4
sbox 0x89 = 0xA7
sbox 0x8a = 0x7E
sbox 0x8b = 0x3D
sbox 0x8c = 0x64
sbox 0x8d = 0x5D
sbox 0x8e = 0x19
sbox 0x8f = 0x73

sbox 0x90 = 0x60
sbox 0x91 = 0x81
sbox 0x92 = 0x4F
sbox 0x93 = 0xDC
sbox 0x94 = 0x22
sbox 0x95 = 0x2A
sbox 0x96 = 0x90
sbox 0x97 = 0x88
sbox 0x98 = 0x46
sbox 0x99 = 0xEE
sbox 0x9a = 0xB8
sbox 0x9b = 0x14
sbox 0x9c = 0xDE
sbox 0x9d = 0x5E
sbox 0x9e = 0x0B
sbox 0x9f = 0xDB

sbox 0xa0 = 0xE0
sbox 0xa1 = 0x32
sbox 0xa2 = 0x3A
sbox 0xa3 = 0x0A
sbox 0xa4 = 0x49
sbox 0xa5 = 0x06
sbox 0xa6 = 0x24
sbox 0xa7 = 0x5C
sbox 0xa8 = 0xC2
sbox 0xa9 = 0xD3
sbox 0xaa = 0xAC
sbox 0xab = 0x62
sbox 0xac = 0x91
sbox 0xad = 0x95
sbox 0xae = 0xE4
sbox 0xaf = 0x79

sbox 0xb0 = 0xE7
sbox 0xb1 = 0xC8
sbox 0xb2 = 0x37
sbox 0xb3 = 0x6D
sbox 0xb4 = 0x8D
sbox 0xb5 = 0xD5
sbox 0xb6 = 0x4E
sbox 0xb7 = 0xA9
sbox 0xb8 = 0x6C
sbox 0xb9 = 0x56
sbox 0xba = 0xF4
sbox 0xbb = 0xEA
sbox 0xbc = 0x65
sbox 0xbd = 0x7A
sbox 0xbe = 0xAE
sbox 0xbf = 0x08

sbox 0xc0 = 0xBA
sbox 0xc1 = 0x78
sbox 0xc2 = 0x25
sbox 0xc3 = 0x2E
sbox 0xc4 = 0x1C
sbox 0xc5 = 0xA6
sbox 0xc6 = 0xB4
sbox 0xc7 = 0xC6
sbox 0xc8 = 0xE8
sbox 0xc9 = 0xDD
sbox 0xca = 0x74
sbox 0xcb = 0x1F
sbox 0xcc = 0x4B
sbox 0xcd = 0xBD
sbox 0xce = 0x8B
sbox 0xcf = 0x8A

sbox 0xd0 = 0x70
sbox 0xd1 = 0x3E
sbox 0xd2 = 0xB5
sbox 0xd3 = 0x66
sbox 0xd4 = 0x48
sbox 0xd5 = 0x03
sbox 0xd6 = 0xF6
sbox 0xd7 = 0x0E
sbox 0xd8 = 0x61
sbox 0xd9 = 0x35
sbox 0xda = 0x57
sbox 0xdb = 0xB9
sbox 0xdc = 0x86
sbox 0xdd = 0xC1
sbox 0xde = 0x1D
sbox 0xdf = 0x9E

sbox 0xe0 = 0xE1
sbox 0xe1 = 0xF8
sbox 0xe2 = 0x98
sbox 0xe3 = 0x11
sbox 0xe4 = 0x69
sbox 0xe5 = 0xD9
sbox 0xe6 = 0x8E
sbox 0xe7 = 0x94
sbox 0xe8 = 0x9B
sbox 0xe9 = 0x1E
sbox 0xea = 0x87
sbox 0xeb = 0xE9
sbox 0xec = 0xCE
sbox 0xed = 0x55
sbox 0xee = 0x28
sbox 0xef = 0xDF

sbox 0xf0 = 0x8C
sbox 0xf1 = 0xA1
sbox 0xf2 = 0x89
sbox 0xf3 = 0x0D
sbox 0xf4 = 0xBF
sbox 0xf5 = 0xE6
sbox 0xf6 = 0x42
sbox 0xf7 = 0x68
sbox 0xf8 = 0x41
sbox 0xf9 = 0x99
sbox 0xfa = 0x2D
sbox 0xfb = 0x0F
sbox 0xfc = 0xB0
sbox 0xfd = 0x54
sbox 0xfe = 0xBB
sbox 0xff = 0x16
sbox _    = error "Illegal lookup in sbox"

invSbox :: Word8 -> Word8
invSbox 0x63 = 0x00
invSbox 0x7C = 0x01
invSbox 0x77 = 0x02
invSbox 0x7B = 0x03
invSbox 0xF2 = 0x04
invSbox 0x6B = 0x05
invSbox 0x6F = 0x06
invSbox 0xC5 = 0x07
invSbox 0x30 = 0x08
invSbox 0x01 = 0x09
invSbox 0x67 = 0x0a
invSbox 0x2B = 0x0b
invSbox 0xFE = 0x0c
invSbox 0xD7 = 0x0d
invSbox 0xAB = 0x0e
invSbox 0x76 = 0x0f

invSbox 0xCA = 0x10
invSbox 0x82 = 0x11
invSbox 0xC9 = 0x12
invSbox 0x7D = 0x13
invSbox 0xFA = 0x14
invSbox 0x59 = 0x15
invSbox 0x47 = 0x16
invSbox 0xF0 = 0x17
invSbox 0xAD = 0x18
invSbox 0xD4 = 0x19
invSbox 0xA2 = 0x1a
invSbox 0xAF = 0x1b
invSbox 0x9C = 0x1c
invSbox 0xA4 = 0x1d
invSbox 0x72 = 0x1e
invSbox 0xC0 = 0x1f

invSbox 0xB7 = 0x20
invSbox 0xFD = 0x21
invSbox 0x93 = 0x22
invSbox 0x26 = 0x23
invSbox 0x36 = 0x24
invSbox 0x3F = 0x25
invSbox 0xF7 = 0x26
invSbox 0xCC = 0x27
invSbox 0x34 = 0x28
invSbox 0xA5 = 0x29
invSbox 0xE5 = 0x2a
invSbox 0xF1 = 0x2b
invSbox 0x71 = 0x2c
invSbox 0xD8 = 0x2d
invSbox 0x31 = 0x2e
invSbox 0x15 = 0x2f

invSbox 0x04 = 0x30
invSbox 0xC7 = 0x31
invSbox 0x23 = 0x32
invSbox 0xC3 = 0x33
invSbox 0x18 = 0x34
invSbox 0x96 = 0x35
invSbox 0x05 = 0x36
invSbox 0x9A = 0x37
invSbox 0x07 = 0x38
invSbox 0x12 = 0x39
invSbox 0x80 = 0x3a
invSbox 0xE2 = 0x3b
invSbox 0xEB = 0x3c
invSbox 0x27 = 0x3d
invSbox 0xB2 = 0x3e
invSbox 0x75 = 0x3f

invSbox 0x09 = 0x40
invSbox 0x83 = 0x41
invSbox 0x2C = 0x42
invSbox 0x1A = 0x43
invSbox 0x1B = 0x44
invSbox 0x6E = 0x45
invSbox 0x5A = 0x46
invSbox 0xA0 = 0x47
invSbox 0x52 = 0x48
invSbox 0x3B = 0x49
invSbox 0xD6 = 0x4a
invSbox 0xB3 = 0x4b
invSbox 0x29 = 0x4c
invSbox 0xE3 = 0x4d
invSbox 0x2F = 0x4e
invSbox 0x84 = 0x4f

invSbox 0x53 = 0x50
invSbox 0xD1 = 0x51
invSbox 0x00 = 0x52
invSbox 0xED = 0x53
invSbox 0x20 = 0x54
invSbox 0xFC = 0x55
invSbox 0xB1 = 0x56
invSbox 0x5B = 0x57
invSbox 0x6A = 0x58
invSbox 0xCB = 0x59
invSbox 0xBE = 0x5a
invSbox 0x39 = 0x5b
invSbox 0x4A = 0x5c
invSbox 0x4C = 0x5d
invSbox 0x58 = 0x5e
invSbox 0xCF = 0x5f

invSbox 0xD0 = 0x60
invSbox 0xEF = 0x61
invSbox 0xAA = 0x62
invSbox 0xFB = 0x63
invSbox 0x43 = 0x64
invSbox 0x4D = 0x65
invSbox 0x33 = 0x66
invSbox 0x85 = 0x67
invSbox 0x45 = 0x68
invSbox 0xF9 = 0x69
invSbox 0x02 = 0x6a
invSbox 0x7F = 0x6b
invSbox 0x50 = 0x6c
invSbox 0x3C = 0x6d
invSbox 0x9F = 0x6e
invSbox 0xA8 = 0x6f

invSbox 0x51 = 0x70
invSbox 0xA3 = 0x71
invSbox 0x40 = 0x72
invSbox 0x8F = 0x73
invSbox 0x92 = 0x74
invSbox 0x9D = 0x75
invSbox 0x38 = 0x76
invSbox 0xF5 = 0x77
invSbox 0xBC = 0x78
invSbox 0xB6 = 0x79
invSbox 0xDA = 0x7a
invSbox 0x21 = 0x7b
invSbox 0x10 = 0x7c
invSbox 0xFF = 0x7d
invSbox 0xF3 = 0x7e
invSbox 0xD2 = 0x7f

invSbox 0xCD = 0x80
invSbox 0x0C = 0x81
invSbox 0x13 = 0x82
invSbox 0xEC = 0x83
invSbox 0x5F = 0x84
invSbox 0x97 = 0x85
invSbox 0x44 = 0x86
invSbox 0x17 = 0x87
invSbox 0xC4 = 0x88
invSbox 0xA7 = 0x89
invSbox 0x7E = 0x8a
invSbox 0x3D = 0x8b
invSbox 0x64 = 0x8c
invSbox 0x5D = 0x8d
invSbox 0x19 = 0x8e
invSbox 0x73 = 0x8f

invSbox 0x60 = 0x90
invSbox 0x81 = 0x91
invSbox 0x4F = 0x92
invSbox 0xDC = 0x93
invSbox 0x22 = 0x94
invSbox 0x2A = 0x95
invSbox 0x90 = 0x96
invSbox 0x88 = 0x97
invSbox 0x46 = 0x98
invSbox 0xEE = 0x99
invSbox 0xB8 = 0x9a
invSbox 0x14 = 0x9b
invSbox 0xDE = 0x9c
invSbox 0x5E = 0x9d
invSbox 0x0B = 0x9e
invSbox 0xDB = 0x9f

invSbox 0xE0 = 0xa0
invSbox 0x32 = 0xa1
invSbox 0x3A = 0xa2
invSbox 0x0A = 0xa3
invSbox 0x49 = 0xa4
invSbox 0x06 = 0xa5
invSbox 0x24 = 0xa6
invSbox 0x5C = 0xa7
invSbox 0xC2 = 0xa8
invSbox 0xD3 = 0xa9
invSbox 0xAC = 0xaa
invSbox 0x62 = 0xab
invSbox 0x91 = 0xac
invSbox 0x95 = 0xad
invSbox 0xE4 = 0xae
invSbox 0x79 = 0xaf

invSbox 0xE7 = 0xb0
invSbox 0xC8 = 0xb1
invSbox 0x37 = 0xb2
invSbox 0x6D = 0xb3
invSbox 0x8D = 0xb4
invSbox 0xD5 = 0xb5
invSbox 0x4E = 0xb6
invSbox 0xA9 = 0xb7
invSbox 0x6C = 0xb8
invSbox 0x56 = 0xb9
invSbox 0xF4 = 0xba
invSbox 0xEA = 0xbb
invSbox 0x65 = 0xbc
invSbox 0x7A = 0xbd
invSbox 0xAE = 0xbe
invSbox 0x08 = 0xbf

invSbox 0xBA = 0xc0
invSbox 0x78 = 0xc1
invSbox 0x25 = 0xc2
invSbox 0x2E = 0xc3
invSbox 0x1C = 0xc4
invSbox 0xA6 = 0xc5
invSbox 0xB4 = 0xc6
invSbox 0xC6 = 0xc7
invSbox 0xE8 = 0xc8
invSbox 0xDD = 0xc9
invSbox 0x74 = 0xca
invSbox 0x1F = 0xcb
invSbox 0x4B = 0xcc
invSbox 0xBD = 0xcd
invSbox 0x8B = 0xce
invSbox 0x8A = 0xcf

invSbox 0x70 = 0xd0
invSbox 0x3E = 0xd1
invSbox 0xB5 = 0xd2
invSbox 0x66 = 0xd3
invSbox 0x48 = 0xd4
invSbox 0x03 = 0xd5
invSbox 0xF6 = 0xd6
invSbox 0x0E = 0xd7
invSbox 0x61 = 0xd8
invSbox 0x35 = 0xd9
invSbox 0x57 = 0xda
invSbox 0xB9 = 0xdb
invSbox 0x86 = 0xdc
invSbox 0xC1 = 0xdd
invSbox 0x1D = 0xde
invSbox 0x9E = 0xdf

invSbox 0xE1 = 0xe0
invSbox 0xF8 = 0xe1
invSbox 0x98 = 0xe2
invSbox 0x11 = 0xe3
invSbox 0x69 = 0xe4
invSbox 0xD9 = 0xe5
invSbox 0x8E = 0xe6
invSbox 0x94 = 0xe7
invSbox 0x9B = 0xe8
invSbox 0x1E = 0xe9
invSbox 0x87 = 0xea
invSbox 0xE9 = 0xeb
invSbox 0xCE = 0xec
invSbox 0x55 = 0xed
invSbox 0x28 = 0xee
invSbox 0xDF = 0xef

invSbox 0x8C = 0xf0
invSbox 0xA1 = 0xf1
invSbox 0x89 = 0xf2
invSbox 0x0D = 0xf3
invSbox 0xBF = 0xf4
invSbox 0xE6 = 0xf5
invSbox 0x42 = 0xf6
invSbox 0x68 = 0xf7
invSbox 0x41 = 0xf8
invSbox 0x99 = 0xf9
invSbox 0x2D = 0xfa
invSbox 0x0F = 0xfb
invSbox 0xB0 = 0xfc
invSbox 0x54 = 0xfd
invSbox 0xBB = 0xfe
invSbox 0x16 = 0xff
invSbox _    = error "Illegal lookup in invSbox"

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
                                      (rotWord1 s1)
                                      (rotWord2 s2)
                                      (rotWord3 s3)
{-# INLINE shiftRows #-}

invShiftRows :: STATE -> STATE
invShiftRows (STATE s0 s1 s2 s3) = STATE s0
                                      (rotWord3 s1)
                                      (rotWord2 s2)
                                      (rotWord1 s3)
{-# INLINE invShiftRows #-}

mixColumns :: STATE -> STATE
mixColumns (STATE (SplitWord32 s00 s01 s02 s03)
                  (SplitWord32 s10 s11 s12 s13)
                  (SplitWord32 s20 s21 s22 s23)
                  (SplitWord32 s30 s31 s32 s33)) =
            STATE (SplitWord32 r00 r01 r02 r03)
                  (SplitWord32 r10 r11 r12 r13)
                  (SplitWord32 r20 r21 r22 r23)
                  (SplitWord32 r30 r31 r32 r33)
  where
    mixColumn :: (Word8,Word8,Word8,Word8) -> (Word8,Word8,Word8,Word8)
    mixColumn (s0,s1,s2,s3) =
      ( xtime02 s0 `xor` xtime03 s1 `xor` s2         `xor` s3
      , s0         `xor` xtime02 s1 `xor` xtime03 s2 `xor` s3
      , s0         `xor` s1         `xor` xtime02 s2 `xor` xtime03 s3
      , xtime03 s0 `xor` s1         `xor` s2         `xor` xtime02 s3      )
    (r00, r10, r20, r30) = mixColumn (s00, s10, s20, s30)
    (r01, r11, r21, r31) = mixColumn (s01, s11, s21, s31)
    (r02, r12, r22, r32) = mixColumn (s02, s12, s22, s32)
    (r03, r13, r23, r33) = mixColumn (s03, s13, s23, s33)
{-# INLINEABLE mixColumns #-}

invMixColumns :: STATE -> STATE
invMixColumns (STATE (SplitWord32 r00 r01 r02 r03)
                     (SplitWord32 r10 r11 r12 r13)
                     (SplitWord32 r20 r21 r22 r23)
                     (SplitWord32 r30 r31 r32 r33)) =
               STATE (SplitWord32 s00 s01 s02 s03)
                     (SplitWord32 s10 s11 s12 s13)
                     (SplitWord32 s20 s21 s22 s23)
                     (SplitWord32 s30 s31 s32 s33)
  where
    invMixColumn :: (Word8,Word8,Word8,Word8) -> (Word8,Word8,Word8,Word8)
    invMixColumn (s0,s1,s2,s3) =
      ( xtime0e s0 `xor` xtime0b s1 `xor` xtime0d s2 `xor` xtime09 s3
      , xtime09 s0 `xor` xtime0e s1 `xor` xtime0b s2 `xor` xtime0d s3
      , xtime0d s0 `xor` xtime09 s1 `xor` xtime0e s2 `xor` xtime0b s3
      , xtime0b s0 `xor` xtime0d s1 `xor` xtime09 s2 `xor` xtime0e s3
      )

    (s00, s10, s20, s30) = invMixColumn (r00, r10, r20, r30)
    (s01, s11, s21, s31) = invMixColumn (r01, r11, r21, r31)
    (s02, s12, s22, s32) = invMixColumn (r02, r12, r22, r32)
    (s03, s13, s23, s33) = invMixColumn (r03, r13, r23, r33)
{-# INLINEABLE invMixColumns #-}

addRoundKey :: STATE -> STATE -> STATE
addRoundKey (STATE s0 s1 s2 s3)
            (STATE k0 k1 k2 k3) =
  STATE (s0 `xor'` k0) (s1 `xor'` k1) (s2 `xor'` k2) (s3 `xor'` k3)
{-# INLINEABLE addRoundKey #-}

invAddRoundKey :: STATE -> STATE -> STATE
invAddRoundKey = addRoundKey

transpose :: STATE -> STATE
transpose (STATE (SplitWord32 s00 s01 s02 s03)
                 (SplitWord32 s10 s11 s12 s13)
                 (SplitWord32 s20 s21 s22 s23)
                 (SplitWord32 s30 s31 s32 s33)) =
           STATE (SplitWord32 s00 s10 s20 s30)
                 (SplitWord32 s01 s11 s21 s31)
                 (SplitWord32 s02 s12 s22 s32)
                 (SplitWord32 s03 s13 s23 s33)
{-# INLINEABLE transpose #-}

invSubWord :: SplitWord32 -> SplitWord32
invSubWord (SplitWord32 w0 w1 w2 w3) = SplitWord32 (invSbox w0)
                                                   (invSbox w1)
                                                   (invSbox w2)
                                                   (invSbox w3)
{-# INLINE invSubWord #-}

subWord :: SplitWord32 -> SplitWord32
subWord (SplitWord32 w0 w1 w2 w3) = SplitWord32 (sbox w0)
                                                (sbox w1)
                                                (sbox w2)
                                                (sbox w3)
{-# INLINE subWord #-}

rotWord1 :: SplitWord32 -> SplitWord32
rotWord1 (SplitWord32 w0 w1 w2 w3) = SplitWord32 w1 w2 w3 w0
{-# INLINE rotWord1 #-}

rotWord2 :: SplitWord32 -> SplitWord32
rotWord2 (SplitWord32 w0 w1 w2 w3) = SplitWord32 w2 w3 w0 w1
{-# INLINE rotWord2 #-}

rotWord3 :: SplitWord32 -> SplitWord32
rotWord3 (SplitWord32 w0 w1 w2 w3) = SplitWord32 w3 w0 w1 w2
{-# INLINE rotWord3 #-}

rcon :: Int -> SplitWord32
rcon i = SplitWord32 (xpower (i-1) 0x01) 0x00 0x00 0x00
{-# INLINE rcon #-}

xorState :: STATE -> STATE -> STATE
xorState = addRoundKey

expand128 :: KEY128 -> Expanded128
expand128 (KEY128 w0 w1 w2 w3) =
    Expanded128 (transpose s00)
                (transpose s01)
                (transpose s02)
                (transpose s03)
                (transpose s04)
                (transpose s05)
                (transpose s06)
                (transpose s07)
                (transpose s08)
                (transpose s09)
                (transpose s10)
    where
      whennk i w = subWord (rotWord1 w) `xor'` rcon (i `div` 4)
      next :: Int -> STATE -> STATE
      next i  (STATE s0 s1 s2 s3) =
               STATE t0 t1 t2 t3
        where
          t0 = s0 `xor'` (whennk (i*4) s3)
          t1 = s1 `xor'` t0
          t2 = s2 `xor'` t1
          t3 = s3 `xor'` t2
      s00 = STATE w0 w1 w2 w3
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
  = transpose s10
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
  = transpose s10
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

expand192 :: KEY192 -> Expanded192
expand192 (KEY192 w0 w1 w2 w3 w4 w5) =
    Expanded192 (transpose s00)
                (transpose s01)
                (transpose s02)
                (transpose s03)
                (transpose s04)
                (transpose s05)
                (transpose s06)
                (transpose s07)
                (transpose s08)
                (transpose s09)
                (transpose s10)
                (transpose s11)
                (transpose s12)
    where
      whennk i w = subWord (rotWord1 w) `xor'` rcon i
      next :: Int
           -> (SplitWord32, SplitWord32, SplitWord32 ,SplitWord32 ,SplitWord32 ,SplitWord32)
           -> (SplitWord32, SplitWord32, SplitWord32 ,SplitWord32 ,SplitWord32 ,SplitWord32)
      next i  (s0,s1,s2,s3,s4,s5) =
              (t0,t1,t2,t3,t4,t5)
        where
          t0 = s0 `xor'` (whennk i s5)
          t1 = s1 `xor'` t0
          t2 = s2 `xor'` t1
          t3 = s3 `xor'` t2
          t4 = s4 `xor'` t3
          t5 = s5 `xor'` t4
      s00 = STATE w0 w1 w2 w3
      (t00,t01,t02,t03,t04,t05) = next 1 (w0,w1,w2,w3,w4,w5)
      s01 = STATE w4 w5 t00 t01
      s02 = STATE t02 t03 t04 t05
      (t10,t11,t12,t13,t14,t15) = next 2 (t00,t01,t02,t03,t04,t05)
      (t20,t21,t22,t23,t24,t25) = next 3 (t10,t11,t12,t13,t14,t15)
      s03 = STATE t10 t11 t12 t13
      s04 = STATE t14 t15 t20 t21
      s05 = STATE t22 t23 t24 t25
      (t30,t31,t32,t33,t34,t35) = next 4 (t20,t21,t22,t23,t24,t25)
      (t40,t41,t42,t43,t44,t45) = next 5 (t30,t31,t32,t33,t34,t35)
      s06 = STATE t30 t31 t32 t33
      s07 = STATE t34 t35 t40 t41
      s08 = STATE t42 t43 t44 t45
      (t50,t51,t52,t53,t54,t55) = next 6 (t40,t41,t42,t43,t44,t45)
      (t60,t61,t62,t63,t64,t65) = next 7 (t50,t51,t52,t53,t54,t55)
      s09 = STATE t50 t51 t52 t53
      s10 = STATE t54 t55 t60 t61
      s11 = STATE t62 t63 t64 t65
      s12 = STATE t0 t1 t2 t3
        where t0 = t60 `xor'` (whennk 8 t65)
              t1 = t61 `xor'` t0
              t2 = t62 `xor'` t1
              t3 = t63 `xor'` t2

encrypt192 :: STATE -> Expanded192 -> STATE
encrypt192 inp (Expanded192 k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k10
                            k11 k12) = transpose s12
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
                           k11 k12) = transpose s12
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

expand256 :: KEY256 -> Expanded256
expand256 (KEY256 w0 w1 w2 w3 w4 w5 w6 w7) =
    Expanded256 (transpose s00)
                (transpose s01)
                (transpose s02)
                (transpose s03)
                (transpose s04)
                (transpose s05)
                (transpose s06)
                (transpose s07)
                (transpose s08)
                (transpose s09)
                (transpose s10)
                (transpose s11)
                (transpose s12)
                (transpose s13)
                (transpose s14)
    where
      whennk i w = (subWord (rotWord1 w)) `xor'` rcon i
      next1 :: Int -> STATE -> STATE -> STATE
      next1 i (STATE r0 r1 r2 r3)
              (STATE _ _ _ t3) =
              (STATE s0 s1 s2 s3)
        where
          s0 = r0 `xor'` (whennk i t3)
          s1 = r1 `xor'` s0
          s2 = r2 `xor'` s1
          s3 = r3 `xor'` s2
      next2 :: STATE -> STATE -> STATE
      next2 (STATE r0 r1 r2 r3)
            (STATE _ _ _ t3) =
            (STATE s0 s1 s2 s3)
        where
          s0 = r0 `xor'` subWord t3
          s1 = r1 `xor'` s0
          s2 = r2 `xor'` s1
          s3 = r3 `xor'` s2
      s00 = STATE w0 w1 w2 w3
      s01 = STATE w4 w5 w6 w7
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
                           k11 k12 k13 k14) = transpose s14
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
                           k11 k12 k13 k14) = transpose s14
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
