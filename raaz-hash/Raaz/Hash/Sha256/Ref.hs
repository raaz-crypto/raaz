{-|

This module gives the reference implementation of the sha256
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha256.Ref
       ( sha256CompressSingle
       ) where

import Control.Applicative
import Data.Bits
import Data.Word

import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha256.Type ( SHA256(..) )

-- | Compresses one block.
sha256CompressSingle :: SHA256
                   -> CryptoPtr
                   -> IO SHA256
sha256CompressSingle sha256 cptr =
         sha256round sha256
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

-- | The sigle round of SHA256
sha256round :: SHA256 -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32)-> (BE Word32) -> (BE Word32)
             -> SHA256
sha256round h0 w0 w1 w2 w3 w4 w5 w6 w7 w8
          w9 w10 w11 w12 w13 w14 w15 = addHash h0 h64
            where
              sigS0,sigS1 :: (BE Word32) -> (BE Word32)
              sigS0 x = rotateR x 7  `xor` rotateR x 18 `xor` shiftR x 3
              sigS1 x = rotateR x 17 `xor` rotateR x 19 `xor` shiftR x 10
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
              addHash :: SHA256 -> SHA256 -> SHA256
              addHash (SHA256 a b c d e f g h) (SHA256 a' b' c' d' e' f' g' h') =
                SHA256 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')

trans :: Int -> SHA256 -> (BE Word32) -> SHA256
trans r (SHA256 a b c d e f g h) w' = SHA256 a' b' c' d' e' f' g' h'
  where
    sigB0,sigB1 :: (BE Word32) -> (BE Word32)
    sigB0 x = rotateR x 2  `xor` rotateR x 13 `xor` rotateR x 22
    sigB1 x = rotateR x 6  `xor` rotateR x 11 `xor` rotateR x 25
    t1 = h + sigB1 e + ((e .&. f) `xor` (complement e .&. g)) + sha256constant r + w'
    t2 = sigB0 a + ((a .&. (b .|. c)) .|. (b .&. c))
    a' = t1 + t2
    b' = a
    c' = b
    d' = c
    e' = d + t1
    f' = e
    g' = f
    h' = g

sha256constant :: Int -> (BE Word32)
sha256constant i  |  i == 0     =   0x428a2f98
                  |  i == 1     =   0x71374491
                  |  i == 2     =   0xb5c0fbcf
                  |  i == 3     =   0xe9b5dba5
                  |  i == 4     =   0x3956c25b
                  |  i == 5     =   0x59f111f1
                  |  i == 6     =   0x923f82a4
                  |  i == 7     =   0xab1c5ed5
                  |  i == 8     =   0xd807aa98
                  |  i == 9     =   0x12835b01
                  |  i == 10    =   0x243185be
                  |  i == 11    =   0x550c7dc3
                  |  i == 12    =   0x72be5d74
                  |  i == 13    =   0x80deb1fe
                  |  i == 14    =   0x9bdc06a7
                  |  i == 15    =   0xc19bf174
                  |  i == 16    =   0xe49b69c1
                  |  i == 17    =   0xefbe4786
                  |  i == 18    =   0x0fc19dc6
                  |  i == 19    =   0x240ca1cc
                  |  i == 20    =   0x2de92c6f
                  |  i == 21    =   0x4a7484aa
                  |  i == 22    =   0x5cb0a9dc
                  |  i == 23    =   0x76f988da
                  |  i == 24    =   0x983e5152
                  |  i == 25    =   0xa831c66d
                  |  i == 26    =   0xb00327c8
                  |  i == 27    =   0xbf597fc7
                  |  i == 28    =   0xc6e00bf3
                  |  i == 29    =   0xd5a79147
                  |  i == 30    =   0x06ca6351
                  |  i == 31    =   0x14292967
                  |  i == 32    =   0x27b70a85
                  |  i == 33    =   0x2e1b2138
                  |  i == 34    =   0x4d2c6dfc
                  |  i == 35    =   0x53380d13
                  |  i == 36    =   0x650a7354
                  |  i == 37    =   0x766a0abb
                  |  i == 38    =   0x81c2c92e
                  |  i == 39    =   0x92722c85
                  |  i == 40    =   0xa2bfe8a1
                  |  i == 41    =   0xa81a664b
                  |  i == 42    =   0xc24b8b70
                  |  i == 43    =   0xc76c51a3
                  |  i == 44    =   0xd192e819
                  |  i == 45    =   0xd6990624
                  |  i == 46    =   0xf40e3585
                  |  i == 47    =   0x106aa070
                  |  i == 48    =   0x19a4c116
                  |  i == 49    =   0x1e376c08
                  |  i == 50    =   0x2748774c
                  |  i == 51    =   0x34b0bcb5
                  |  i == 52    =   0x391c0cb3
                  |  i == 53    =   0x4ed8aa4a
                  |  i == 54    =   0x5b9cca4f
                  |  i == 55    =   0x682e6ff3
                  |  i == 56    =   0x748f82ee
                  |  i == 57    =   0x78a5636f
                  |  i == 58    =   0x84c87814
                  |  i == 59    =   0x8cc70208
                  |  i == 60    =   0x90befffa
                  |  i == 61    =   0xa4506ceb
                  |  i == 62    =   0xbef9a3f7
                  |  i == 63    =   0xc67178f2
                  |  otherwise = error "sha256:ref: Wrong index used for sha256constant"
{-# INLINE sha256constant #-}
