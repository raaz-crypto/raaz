{-|

This module gives the reference implementation of the sha1
hash. Depending on your platform, there might be a more efficient
and/or secure implementation. So you /should not/ be using this code
in production unless you know what you are doing.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha1.Ref
       ( sha1CompressSingle
       ) where

import Control.Applicative
import Data.Bits
import Data.Word

import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Sha1.Type ( SHA1(..) )

-- | Compresses one block.
sha1CompressSingle :: SHA1
                   -> CryptoPtr
                   -> IO SHA1
sha1CompressSingle sha1 cptr = sha1round sha1
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

-- | The sigle round of SHA1
sha1round :: SHA1 -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32) -> (BE Word32) -> (BE Word32)
             -> (BE Word32) -> (BE Word32)-> (BE Word32) -> (BE Word32)
             -> SHA1
sha1round h0 w0 w1 w2 w3 w4 w5 w6 w7 w8
          w9 w10 w11 w12 w13 w14 w15 = addHash h0 h80
            where
              w16 = rotateL (w13 `xor` w8 `xor` w2 `xor` w0) 1
              w17 = rotateL (w14 `xor` w9 `xor` w3 `xor` w1) 1
              w18 = rotateL (w15 `xor` w10 `xor` w4 `xor` w2) 1
              w19 = rotateL (w16 `xor` w11 `xor` w5 `xor` w3) 1
              w20 = rotateL (w17 `xor` w12 `xor` w6 `xor` w4) 1
              w21 = rotateL (w18 `xor` w13 `xor` w7 `xor` w5) 1
              w22 = rotateL (w19 `xor` w14 `xor` w8 `xor` w6) 1
              w23 = rotateL (w20 `xor` w15 `xor` w9 `xor` w7) 1
              w24 = rotateL (w21 `xor` w16 `xor` w10 `xor` w8) 1
              w25 = rotateL (w22 `xor` w17 `xor` w11 `xor` w9) 1
              w26 = rotateL (w23 `xor` w18 `xor` w12 `xor` w10) 1
              w27 = rotateL (w24 `xor` w19 `xor` w13 `xor` w11) 1
              w28 = rotateL (w25 `xor` w20 `xor` w14 `xor` w12) 1
              w29 = rotateL (w26 `xor` w21 `xor` w15 `xor` w13) 1
              w30 = rotateL (w27 `xor` w22 `xor` w16 `xor` w14) 1
              w31 = rotateL (w28 `xor` w23 `xor` w17 `xor` w15) 1
              w32 = rotateL (w29 `xor` w24 `xor` w18 `xor` w16) 1
              w33 = rotateL (w30 `xor` w25 `xor` w19 `xor` w17) 1
              w34 = rotateL (w31 `xor` w26 `xor` w20 `xor` w18) 1
              w35 = rotateL (w32 `xor` w27 `xor` w21 `xor` w19) 1
              w36 = rotateL (w33 `xor` w28 `xor` w22 `xor` w20) 1
              w37 = rotateL (w34 `xor` w29 `xor` w23 `xor` w21) 1
              w38 = rotateL (w35 `xor` w30 `xor` w24 `xor` w22) 1
              w39 = rotateL (w36 `xor` w31 `xor` w25 `xor` w23) 1
              w40 = rotateL (w37 `xor` w32 `xor` w26 `xor` w24) 1
              w41 = rotateL (w38 `xor` w33 `xor` w27 `xor` w25) 1
              w42 = rotateL (w39 `xor` w34 `xor` w28 `xor` w26) 1
              w43 = rotateL (w40 `xor` w35 `xor` w29 `xor` w27) 1
              w44 = rotateL (w41 `xor` w36 `xor` w30 `xor` w28) 1
              w45 = rotateL (w42 `xor` w37 `xor` w31 `xor` w29) 1
              w46 = rotateL (w43 `xor` w38 `xor` w32 `xor` w30) 1
              w47 = rotateL (w44 `xor` w39 `xor` w33 `xor` w31) 1
              w48 = rotateL (w45 `xor` w40 `xor` w34 `xor` w32) 1
              w49 = rotateL (w46 `xor` w41 `xor` w35 `xor` w33) 1
              w50 = rotateL (w47 `xor` w42 `xor` w36 `xor` w34) 1
              w51 = rotateL (w48 `xor` w43 `xor` w37 `xor` w35) 1
              w52 = rotateL (w49 `xor` w44 `xor` w38 `xor` w36) 1
              w53 = rotateL (w50 `xor` w45 `xor` w39 `xor` w37) 1
              w54 = rotateL (w51 `xor` w46 `xor` w40 `xor` w38) 1
              w55 = rotateL (w52 `xor` w47 `xor` w41 `xor` w39) 1
              w56 = rotateL (w53 `xor` w48 `xor` w42 `xor` w40) 1
              w57 = rotateL (w54 `xor` w49 `xor` w43 `xor` w41) 1
              w58 = rotateL (w55 `xor` w50 `xor` w44 `xor` w42) 1
              w59 = rotateL (w56 `xor` w51 `xor` w45 `xor` w43) 1
              w60 = rotateL (w57 `xor` w52 `xor` w46 `xor` w44) 1
              w61 = rotateL (w58 `xor` w53 `xor` w47 `xor` w45) 1
              w62 = rotateL (w59 `xor` w54 `xor` w48 `xor` w46) 1
              w63 = rotateL (w60 `xor` w55 `xor` w49 `xor` w47) 1
              w64 = rotateL (w61 `xor` w56 `xor` w50 `xor` w48) 1
              w65 = rotateL (w62 `xor` w57 `xor` w51 `xor` w49) 1
              w66 = rotateL (w63 `xor` w58 `xor` w52 `xor` w50) 1
              w67 = rotateL (w64 `xor` w59 `xor` w53 `xor` w51) 1
              w68 = rotateL (w65 `xor` w60 `xor` w54 `xor` w52) 1
              w69 = rotateL (w66 `xor` w61 `xor` w55 `xor` w53) 1
              w70 = rotateL (w67 `xor` w62 `xor` w56 `xor` w54) 1
              w71 = rotateL (w68 `xor` w63 `xor` w57 `xor` w55) 1
              w72 = rotateL (w69 `xor` w64 `xor` w58 `xor` w56) 1
              w73 = rotateL (w70 `xor` w65 `xor` w59 `xor` w57) 1
              w74 = rotateL (w71 `xor` w66 `xor` w60 `xor` w58) 1
              w75 = rotateL (w72 `xor` w67 `xor` w61 `xor` w59) 1
              w76 = rotateL (w73 `xor` w68 `xor` w62 `xor` w60) 1
              w77 = rotateL (w74 `xor` w69 `xor` w63 `xor` w61) 1
              w78 = rotateL (w75 `xor` w70 `xor` w64 `xor` w62) 1
              w79 = rotateL (w76 `xor` w71 `xor` w65 `xor` w63) 1
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
              addHash :: SHA1 -> SHA1 -> SHA1
              addHash (SHA1 a b c d e) (SHA1 a' b' c' d' e') =
                  SHA1 (a+a') (b+b') (c+c') (d+d') (e+e')

trans :: Int -> SHA1 -> (BE Word32) -> SHA1
trans r (SHA1 a b c d e) w'  = SHA1 a' b' c' d' e'
  where f t x y z
          | t <= 19   = (x .&. y) `xor` (complement x .&. z)
          | t <= 39   =  x `xor` y `xor` z
          | t <= 59   = (x .&. (y .|. z)) .|. (y .&. z)
          | t <= 79   =  x `xor` y `xor` z
          | otherwise = error "sha1:ref: Wrong index used for trans"
        constant t  | t <= 19    = 0x5a827999 :: (BE Word32)
                    | t <= 39    = 0x6ed9eba1 :: (BE Word32)
                    | t <= 59    = 0x8f1bbcdc :: (BE Word32)
                    | t <= 79    = 0xca62c1d6 :: (BE Word32)
                    | otherwise = error "sha1:ref: Wrong index used for trans"
        a' = rotateL a 5 + f r b c d + e + constant r + w'
        b' = a
        c' = rotateL b 30
        d' = c
        e' = d
