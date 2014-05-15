{-|

This module gives the reference implementation of the sha512
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha512.Ref
       ( sha512CompressSingle
       ) where

import Control.Applicative
import Data.Bits

import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Hash.Sha512.Type(SHA512(..))

-- | Compresses one block.
sha512CompressSingle :: SHA512
                     -> CryptoPtr
                     -> IO SHA512
sha512CompressSingle sha512 cptr =
         sha512round sha512
         <$> load cptr
         <*> loadFromIndex cptr 1
         <*> loadFromIndex cptr 2
         <*> loadFromIndex cptr 3
         <*> loadFromIndex cptr 4
         <*> loadFromIndex cptr 5
         <*> loadFromIndex cptr 6
         <*> loadFromIndex cptr 7
         <*> loadFromIndex cptr 8
         <*> loadFromIndex cptr 9
         <*> loadFromIndex cptr 10
         <*> loadFromIndex cptr 11
         <*> loadFromIndex cptr 12
         <*> loadFromIndex cptr 13
         <*> loadFromIndex cptr 14
         <*> loadFromIndex cptr 15

-- | The sigle round of SHA512
sha512round :: SHA512 -> Word64BE -> Word64BE -> Word64BE -> Word64BE
             -> Word64BE -> Word64BE -> Word64BE -> Word64BE
             -> Word64BE -> Word64BE -> Word64BE -> Word64BE
             -> Word64BE -> Word64BE-> Word64BE -> Word64BE
             -> SHA512
sha512round h0 w0 w1 w2 w3 w4 w5 w6 w7 w8
          w9 w10 w11 w12 w13 w14 w15 = addHash h0 h80
            where
              sigS0,sigS1 :: Word64BE -> Word64BE
              sigS0 x = rotateR x 1  `xor` rotateR x 8  `xor` shiftR  x 7
              sigS1 x = rotateR x 19 `xor` rotateR x 61 `xor` shiftR  x 6
              w16 = sigS1 w14 + w9 + sigS0 w1 + w0
              w17 = sigS1 w15 + w10 + sigS0 w2 + w1
              w18 = sigS1 w16 + w11 + sigS0 w3 + w2
              w19 = sigS1 w17 + w12 + sigS0 w4 + w3
              w20 = sigS1 w18 + w13 + sigS0 w5 + w4
              w21 = sigS1 w19 + w14 + sigS0 w6 + w5
              w22 = sigS1 w20 + w15 + sigS0 w7 + w6
              w23 = sigS1 w21 + w16 + sigS0 w8 + w7
              w24 = sigS1 w22 + w17 + sigS0 w9 + w8
              w25 = sigS1 w23 + w18 + sigS0 w10 + w9
              w26 = sigS1 w24 + w19 + sigS0 w11 + w10
              w27 = sigS1 w25 + w20 + sigS0 w12 + w11
              w28 = sigS1 w26 + w21 + sigS0 w13 + w12
              w29 = sigS1 w27 + w22 + sigS0 w14 + w13
              w30 = sigS1 w28 + w23 + sigS0 w15 + w14
              w31 = sigS1 w29 + w24 + sigS0 w16 + w15
              w32 = sigS1 w30 + w25 + sigS0 w17 + w16
              w33 = sigS1 w31 + w26 + sigS0 w18 + w17
              w34 = sigS1 w32 + w27 + sigS0 w19 + w18
              w35 = sigS1 w33 + w28 + sigS0 w20 + w19
              w36 = sigS1 w34 + w29 + sigS0 w21 + w20
              w37 = sigS1 w35 + w30 + sigS0 w22 + w21
              w38 = sigS1 w36 + w31 + sigS0 w23 + w22
              w39 = sigS1 w37 + w32 + sigS0 w24 + w23
              w40 = sigS1 w38 + w33 + sigS0 w25 + w24
              w41 = sigS1 w39 + w34 + sigS0 w26 + w25
              w42 = sigS1 w40 + w35 + sigS0 w27 + w26
              w43 = sigS1 w41 + w36 + sigS0 w28 + w27
              w44 = sigS1 w42 + w37 + sigS0 w29 + w28
              w45 = sigS1 w43 + w38 + sigS0 w30 + w29
              w46 = sigS1 w44 + w39 + sigS0 w31 + w30
              w47 = sigS1 w45 + w40 + sigS0 w32 + w31
              w48 = sigS1 w46 + w41 + sigS0 w33 + w32
              w49 = sigS1 w47 + w42 + sigS0 w34 + w33
              w50 = sigS1 w48 + w43 + sigS0 w35 + w34
              w51 = sigS1 w49 + w44 + sigS0 w36 + w35
              w52 = sigS1 w50 + w45 + sigS0 w37 + w36
              w53 = sigS1 w51 + w46 + sigS0 w38 + w37
              w54 = sigS1 w52 + w47 + sigS0 w39 + w38
              w55 = sigS1 w53 + w48 + sigS0 w40 + w39
              w56 = sigS1 w54 + w49 + sigS0 w41 + w40
              w57 = sigS1 w55 + w50 + sigS0 w42 + w41
              w58 = sigS1 w56 + w51 + sigS0 w43 + w42
              w59 = sigS1 w57 + w52 + sigS0 w44 + w43
              w60 = sigS1 w58 + w53 + sigS0 w45 + w44
              w61 = sigS1 w59 + w54 + sigS0 w46 + w45
              w62 = sigS1 w60 + w55 + sigS0 w47 + w46
              w63 = sigS1 w61 + w56 + sigS0 w48 + w47
              w64 = sigS1 w62 + w57 + sigS0 w49 + w48
              w65 = sigS1 w63 + w58 + sigS0 w50 + w49
              w66 = sigS1 w64 + w59 + sigS0 w51 + w50
              w67 = sigS1 w65 + w60 + sigS0 w52 + w51
              w68 = sigS1 w66 + w61 + sigS0 w53 + w52
              w69 = sigS1 w67 + w62 + sigS0 w54 + w53
              w70 = sigS1 w68 + w63 + sigS0 w55 + w54
              w71 = sigS1 w69 + w64 + sigS0 w56 + w55
              w72 = sigS1 w70 + w65 + sigS0 w57 + w56
              w73 = sigS1 w71 + w66 + sigS0 w58 + w57
              w74 = sigS1 w72 + w67 + sigS0 w59 + w58
              w75 = sigS1 w73 + w68 + sigS0 w60 + w59
              w76 = sigS1 w74 + w69 + sigS0 w61 + w60
              w77 = sigS1 w75 + w70 + sigS0 w62 + w61
              w78 = sigS1 w76 + w71 + sigS0 w63 + w62
              w79 = sigS1 w77 + w72 + sigS0 w64 + w63
              h1  = trans 0 h0 w0
              h2  = trans 1 h1 w1
              h3  = trans 2 h2 w2
              h4  = trans 3 h3 w3
              h5  = trans 4 h4 w4
              h6  = trans 5 h5 w5
              h7  = trans 6 h6 w6
              h8  = trans 7 h7 w7
              h9  = trans 8 h8 w8
              h10 = trans 9 h9 w9
              h11 = trans 10 h10 w10
              h12 = trans 11 h11 w11
              h13 = trans 12 h12 w12
              h14 = trans 13 h13 w13
              h15 = trans 14 h14 w14
              h16 = trans 15 h15 w15
              h17 = trans 16 h16 w16
              h18 = trans 17 h17 w17
              h19 = trans 18 h18 w18
              h20 = trans 19 h19 w19
              h21 = trans 20 h20 w20
              h22 = trans 21 h21 w21
              h23 = trans 22 h22 w22
              h24 = trans 23 h23 w23
              h25 = trans 24 h24 w24
              h26 = trans 25 h25 w25
              h27 = trans 26 h26 w26
              h28 = trans 27 h27 w27
              h29 = trans 28 h28 w28
              h30 = trans 29 h29 w29
              h31 = trans 30 h30 w30
              h32 = trans 31 h31 w31
              h33 = trans 32 h32 w32
              h34 = trans 33 h33 w33
              h35 = trans 34 h34 w34
              h36 = trans 35 h35 w35
              h37 = trans 36 h36 w36
              h38 = trans 37 h37 w37
              h39 = trans 38 h38 w38
              h40 = trans 39 h39 w39
              h41 = trans 40 h40 w40
              h42 = trans 41 h41 w41
              h43 = trans 42 h42 w42
              h44 = trans 43 h43 w43
              h45 = trans 44 h44 w44
              h46 = trans 45 h45 w45
              h47 = trans 46 h46 w46
              h48 = trans 47 h47 w47
              h49 = trans 48 h48 w48
              h50 = trans 49 h49 w49
              h51 = trans 50 h50 w50
              h52 = trans 51 h51 w51
              h53 = trans 52 h52 w52
              h54 = trans 53 h53 w53
              h55 = trans 54 h54 w54
              h56 = trans 55 h55 w55
              h57 = trans 56 h56 w56
              h58 = trans 57 h57 w57
              h59 = trans 58 h58 w58
              h60 = trans 59 h59 w59
              h61 = trans 60 h60 w60
              h62 = trans 61 h61 w61
              h63 = trans 62 h62 w62
              h64 = trans 63 h63 w63
              h65 = trans 64 h64 w64
              h66 = trans 65 h65 w65
              h67 = trans 66 h66 w66
              h68 = trans 67 h67 w67
              h69 = trans 68 h68 w68
              h70 = trans 69 h69 w69
              h71 = trans 70 h70 w70
              h72 = trans 71 h71 w71
              h73 = trans 72 h72 w72
              h74 = trans 73 h73 w73
              h75 = trans 74 h74 w74
              h76 = trans 75 h75 w75
              h77 = trans 76 h76 w76
              h78 = trans 77 h77 w77
              h79 = trans 78 h78 w78
              h80 = trans 79 h79 w79
              addHash :: SHA512 -> SHA512 -> SHA512
              addHash (SHA512 a b c d e f g h) (SHA512 a' b' c' d' e' f' g' h') =
                SHA512 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')

trans :: Int -> SHA512 -> Word64BE -> SHA512
trans r (SHA512 a b c d e f g h) w' = SHA512 a' b' c' d' e' f' g' h'
  where
    sigB0,sigB1 :: Word64BE -> Word64BE
    sigB0 x = rotateR x 28 `xor` rotateR x 34 `xor` rotateR x 39
    sigB1 x = rotateR x 14 `xor` rotateR x 18 `xor` rotateR x 41
    t1 = h + sigB1 e + ((e .&. f) `xor` (complement e .&. g)) + sha512constant r + w'
    t2 = sigB0 a + ((a .&. (b .|. c)) .|. (b .&. c))
    a' = t1 + t2
    b' = a
    c' = b
    d' = c
    e' = d + t1
    f' = e
    g' = f
    h' = g

sha512constant :: Int -> Word64BE
sha512constant i  |  i == 0     =   0x428a2f98d728ae22
                  |  i == 1     =   0x7137449123ef65cd
                  |  i == 2     =   0xb5c0fbcfec4d3b2f
                  |  i == 3     =   0xe9b5dba58189dbbc
                  |  i == 4     =   0x3956c25bf348b538
                  |  i == 5     =   0x59f111f1b605d019
                  |  i == 6     =   0x923f82a4af194f9b
                  |  i == 7     =   0xab1c5ed5da6d8118
                  |  i == 8     =   0xd807aa98a3030242
                  |  i == 9     =   0x12835b0145706fbe
                  |  i == 10    =   0x243185be4ee4b28c
                  |  i == 11    =   0x550c7dc3d5ffb4e2
                  |  i == 12    =   0x72be5d74f27b896f
                  |  i == 13    =   0x80deb1fe3b1696b1
                  |  i == 14    =   0x9bdc06a725c71235
                  |  i == 15    =   0xc19bf174cf692694
                  |  i == 16    =   0xe49b69c19ef14ad2
                  |  i == 17    =   0xefbe4786384f25e3
                  |  i == 18    =   0x0fc19dc68b8cd5b5
                  |  i == 19    =   0x240ca1cc77ac9c65
                  |  i == 20    =   0x2de92c6f592b0275
                  |  i == 21    =   0x4a7484aa6ea6e483
                  |  i == 22    =   0x5cb0a9dcbd41fbd4
                  |  i == 23    =   0x76f988da831153b5
                  |  i == 24    =   0x983e5152ee66dfab
                  |  i == 25    =   0xa831c66d2db43210
                  |  i == 26    =   0xb00327c898fb213f
                  |  i == 27    =   0xbf597fc7beef0ee4
                  |  i == 28    =   0xc6e00bf33da88fc2
                  |  i == 29    =   0xd5a79147930aa725
                  |  i == 30    =   0x06ca6351e003826f
                  |  i == 31    =   0x142929670a0e6e70
                  |  i == 32    =   0x27b70a8546d22ffc
                  |  i == 33    =   0x2e1b21385c26c926
                  |  i == 34    =   0x4d2c6dfc5ac42aed
                  |  i == 35    =   0x53380d139d95b3df
                  |  i == 36    =   0x650a73548baf63de
                  |  i == 37    =   0x766a0abb3c77b2a8
                  |  i == 38    =   0x81c2c92e47edaee6
                  |  i == 39    =   0x92722c851482353b
                  |  i == 40    =   0xa2bfe8a14cf10364
                  |  i == 41    =   0xa81a664bbc423001
                  |  i == 42    =   0xc24b8b70d0f89791
                  |  i == 43    =   0xc76c51a30654be30
                  |  i == 44    =   0xd192e819d6ef5218
                  |  i == 45    =   0xd69906245565a910
                  |  i == 46    =   0xf40e35855771202a
                  |  i == 47    =   0x106aa07032bbd1b8
                  |  i == 48    =   0x19a4c116b8d2d0c8
                  |  i == 49    =   0x1e376c085141ab53
                  |  i == 50    =   0x2748774cdf8eeb99
                  |  i == 51    =   0x34b0bcb5e19b48a8
                  |  i == 52    =   0x391c0cb3c5c95a63
                  |  i == 53    =   0x4ed8aa4ae3418acb
                  |  i == 54    =   0x5b9cca4f7763e373
                  |  i == 55    =   0x682e6ff3d6b2b8a3
                  |  i == 56    =   0x748f82ee5defb2fc
                  |  i == 57    =   0x78a5636f43172f60
                  |  i == 58    =   0x84c87814a1f0ab72
                  |  i == 59    =   0x8cc702081a6439ec
                  |  i == 60    =   0x90befffa23631e28
                  |  i == 61    =   0xa4506cebde82bde9
                  |  i == 62    =   0xbef9a3f7b2c67915
                  |  i == 63    =   0xc67178f2e372532b
                  |  i == 64    =   0xca273eceea26619c
                  |  i == 65    =   0xd186b8c721c0c207
                  |  i == 66    =   0xeada7dd6cde0eb1e
                  |  i == 67    =   0xf57d4f7fee6ed178
                  |  i == 68    =   0x06f067aa72176fba
                  |  i == 69    =   0x0a637dc5a2c898a6
                  |  i == 70    =   0x113f9804bef90dae
                  |  i == 71    =   0x1b710b35131c471b
                  |  i == 72    =   0x28db77f523047d84
                  |  i == 73    =   0x32caab7b40c72493
                  |  i == 74    =   0x3c9ebe0a15c9bebc
                  |  i == 75    =   0x431d67c49c100d4c
                  |  i == 76    =   0x4cc5d4becb3e42b6
                  |  i == 77    =   0x597f299cfc657e2a
                  |  i == 78    =   0x5fcb6fab3ad6faec
                  |  i == 79    =   0x6c44198c4a475817
                  |  otherwise = error "sha512:ref: Wrong index used for sha512constant"
{-# INLINE sha512constant #-}
