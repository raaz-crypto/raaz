{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Ref.Sha512TH
       ( oneRound
       ) where

import Control.Applicative
import Data.Bits
import Language.Haskell.TH

import Raaz.Types
import Raaz.Util.TH

import Raaz.Hash.Sha

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1 ++ args2) (normalB (LetE <$> roundLoop <*>
                                      [| SHA512
                                         ($(subE "a" [-1]) + $(subE "a" [79]))
                                         ($(subE "b" [-1]) + $(subE "b" [79]))
                                         ($(subE "c" [-1]) + $(subE "c" [79]))
                                         ($(subE "d" [-1]) + $(subE "d" [79]))
                                         ($(subE "e" [-1]) + $(subE "e" [79]))
                                         ($(subE "f" [-1]) + $(subE "f" [79]))
                                         ($(subE "g" [-1]) + $(subE "g" [79]))
                                         ($(subE "h" [-1]) + $(subE "h" [79]))
                                      |])) []
    args1 = map (flip subP [-1]) ["a","b","c","d","e","f","g","h"]
    args2 = map (\i -> subP "m" [i]) [0..15]
    typeSig = sigD name $
              foldl (const . appT wordtype) (conT ''SHA512) [1..24 :: Int]
    wordtype = appT arrowT (conT ''Word64BE)

-- | Unrolls the round loop. Also assumes
-- a__1,b__1,c__1,d__1,e__1,f__1,g__1,h__1 which are the hash values
-- in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = declarations [wdecs,kdecs,adecs,edecs,restdecs] [0..79]
  where
    adecs :: Int -> DecsQ
    adecs i = variable' "a" ''Word64BE body [i]
      where
        body [j] = [| $(t1exp j) + $(t2exp j)
                   :: Word64BE |]
        body _   = error "Unimaginable happended"

    edecs :: Int -> DecsQ
    edecs i = variable' "e" ''Word64BE body [i]
      where
        body [j] = [| $(subE "d" [j-1]) + $(t1exp j)
                   :: Word64BE |]
        body _   = error "Unimaginable happended"

    t1exp :: Int -> ExpQ
    t1exp j = [| $(subE "h" [j-1])
               + $(sigB 1 (subE "e" [j-1]))
               + $(ch (subE "e" [j-1]) (subE "f" [j-1]) (subE "g" [j-1]))
               + $(subE "k" [j])
               + $(subE "w" [j])
               :: Word64BE |]

    t2exp :: Int -> ExpQ
    t2exp j = [| $(sigB 0 (subE "a" [j-1]))
               + $(maj (subE "a" [j-1]) (subE "b" [j-1]) (subE "c" [j-1]))
               :: Word64BE |]


    wdecs :: Int -> DecsQ
    wdecs i = variable' "w" ''Word64BE body [i]
      where
        body [j] | i<16      = subE "m" [j]
                 | otherwise = [| $(sigS 1 (subE "w" [j-2]))  +
                                  $(subE "w" [j-7])           +
                                  $(sigS 0 (subE "w" [j-15])) +
                                  $(subE "w" [j-16])
                                :: Word64BE |]
        body _   = error "Unimaginable happended"

    -- | The round constants for SHA1 hash
    kdecs :: Int -> DecsQ
    kdecs i = variable' "k" ''Word64BE body [i]
      where
        body [0]  = [| 0x428a2f98d728ae22 :: Word64BE |]
        body [1]  = [| 0x7137449123ef65cd :: Word64BE |]
        body [2]  = [| 0xb5c0fbcfec4d3b2f :: Word64BE |]
        body [3]  = [| 0xe9b5dba58189dbbc :: Word64BE |]
        body [4]  = [| 0x3956c25bf348b538 :: Word64BE |]
        body [5]  = [| 0x59f111f1b605d019 :: Word64BE |]
        body [6]  = [| 0x923f82a4af194f9b :: Word64BE |]
        body [7]  = [| 0xab1c5ed5da6d8118 :: Word64BE |]
        body [8]  = [| 0xd807aa98a3030242 :: Word64BE |]
        body [9]  = [| 0x12835b0145706fbe :: Word64BE |]
        body [10] = [| 0x243185be4ee4b28c :: Word64BE |]
        body [11] = [| 0x550c7dc3d5ffb4e2 :: Word64BE |]
        body [12] = [| 0x72be5d74f27b896f :: Word64BE |]
        body [13] = [| 0x80deb1fe3b1696b1 :: Word64BE |]
        body [14] = [| 0x9bdc06a725c71235 :: Word64BE |]
        body [15] = [| 0xc19bf174cf692694 :: Word64BE |]
        body [16] = [| 0xe49b69c19ef14ad2 :: Word64BE |]
        body [17] = [| 0xefbe4786384f25e3 :: Word64BE |]
        body [18] = [| 0x0fc19dc68b8cd5b5 :: Word64BE |]
        body [19] = [| 0x240ca1cc77ac9c65 :: Word64BE |]
        body [20] = [| 0x2de92c6f592b0275 :: Word64BE |]
        body [21] = [| 0x4a7484aa6ea6e483 :: Word64BE |]
        body [22] = [| 0x5cb0a9dcbd41fbd4 :: Word64BE |]
        body [23] = [| 0x76f988da831153b5 :: Word64BE |]
        body [24] = [| 0x983e5152ee66dfab :: Word64BE |]
        body [25] = [| 0xa831c66d2db43210 :: Word64BE |]
        body [26] = [| 0xb00327c898fb213f :: Word64BE |]
        body [27] = [| 0xbf597fc7beef0ee4 :: Word64BE |]
        body [28] = [| 0xc6e00bf33da88fc2 :: Word64BE |]
        body [29] = [| 0xd5a79147930aa725 :: Word64BE |]
        body [30] = [| 0x06ca6351e003826f :: Word64BE |]
        body [31] = [| 0x142929670a0e6e70 :: Word64BE |]
        body [32] = [| 0x27b70a8546d22ffc :: Word64BE |]
        body [33] = [| 0x2e1b21385c26c926 :: Word64BE |]
        body [34] = [| 0x4d2c6dfc5ac42aed :: Word64BE |]
        body [35] = [| 0x53380d139d95b3df :: Word64BE |]
        body [36] = [| 0x650a73548baf63de :: Word64BE |]
        body [37] = [| 0x766a0abb3c77b2a8 :: Word64BE |]
        body [38] = [| 0x81c2c92e47edaee6 :: Word64BE |]
        body [39] = [| 0x92722c851482353b :: Word64BE |]
        body [40] = [| 0xa2bfe8a14cf10364 :: Word64BE |]
        body [41] = [| 0xa81a664bbc423001 :: Word64BE |]
        body [42] = [| 0xc24b8b70d0f89791 :: Word64BE |]
        body [43] = [| 0xc76c51a30654be30 :: Word64BE |]
        body [44] = [| 0xd192e819d6ef5218 :: Word64BE |]
        body [45] = [| 0xd69906245565a910 :: Word64BE |]
        body [46] = [| 0xf40e35855771202a :: Word64BE |]
        body [47] = [| 0x106aa07032bbd1b8 :: Word64BE |]
        body [48] = [| 0x19a4c116b8d2d0c8 :: Word64BE |]
        body [49] = [| 0x1e376c085141ab53 :: Word64BE |]
        body [50] = [| 0x2748774cdf8eeb99 :: Word64BE |]
        body [51] = [| 0x34b0bcb5e19b48a8 :: Word64BE |]
        body [52] = [| 0x391c0cb3c5c95a63 :: Word64BE |]
        body [53] = [| 0x4ed8aa4ae3418acb :: Word64BE |]
        body [54] = [| 0x5b9cca4f7763e373 :: Word64BE |]
        body [55] = [| 0x682e6ff3d6b2b8a3 :: Word64BE |]
        body [56] = [| 0x748f82ee5defb2fc :: Word64BE |]
        body [57] = [| 0x78a5636f43172f60 :: Word64BE |]
        body [58] = [| 0x84c87814a1f0ab72 :: Word64BE |]
        body [59] = [| 0x8cc702081a6439ec :: Word64BE |]
        body [60] = [| 0x90befffa23631e28 :: Word64BE |]
        body [61] = [| 0xa4506cebde82bde9 :: Word64BE |]
        body [62] = [| 0xbef9a3f7b2c67915 :: Word64BE |]
        body [63] = [| 0xc67178f2e372532b :: Word64BE |]
        body [64] = [| 0xca273eceea26619c :: Word64BE |]
        body [65] = [| 0xd186b8c721c0c207 :: Word64BE |]
        body [66] = [| 0xeada7dd6cde0eb1e :: Word64BE |]
        body [67] = [| 0xf57d4f7fee6ed178 :: Word64BE |]
        body [68] = [| 0x06f067aa72176fba :: Word64BE |]
        body [69] = [| 0x0a637dc5a2c898a6 :: Word64BE |]
        body [70] = [| 0x113f9804bef90dae :: Word64BE |]
        body [71] = [| 0x1b710b35131c471b :: Word64BE |]
        body [72] = [| 0x28db77f523047d84 :: Word64BE |]
        body [73] = [| 0x32caab7b40c72493 :: Word64BE |]
        body [74] = [| 0x3c9ebe0a15c9bebc :: Word64BE |]
        body [75] = [| 0x431d67c49c100d4c :: Word64BE |]
        body [76] = [| 0x4cc5d4becb3e42b6 :: Word64BE |]
        body [77] = [| 0x597f299cfc657e2a :: Word64BE |]
        body [78] = [| 0x5fcb6fab3ad6faec :: Word64BE |]
        body [79] = [| 0x6c44198c4a475817 :: Word64BE |]
        body _  = error "Unimaginable happended"

    restdecs :: Int -> DecsQ
    restdecs = permute [ ("h","g")
                       , ("g","f")
                       , ("f","e")
                       , ("d","c")
                       , ("c","b")
                       , ("b","a")
                       ]

ch :: ExpQ -> ExpQ -> ExpQ -> ExpQ
ch x y z = [| ($(x) .&. $(y)) `xor` (complement $(x) .&. $(z)) |]

maj :: ExpQ -> ExpQ -> ExpQ -> ExpQ
maj x y z = [| ($(x) .&. $(y)) `xor` ($(y) .&. $(z)) `xor` ($(z) .&. $(x)) |]

sigB :: Int -> ExpQ -> ExpQ
sigB 0 x = [| rotateR $(x) 28 `xor` rotateR $(x) 34 `xor` rotateR $(x) 39 |]
sigB 1 x = [| rotateR $(x) 14 `xor` rotateR $(x) 18 `xor` rotateR $(x) 41 |]
sigB _ _ = error "Wrong usage of sig function"

sigS :: Int -> ExpQ -> ExpQ
sigS 0 x = [| rotateR $(x) 1  `xor` rotateR $(x) 8  `xor` shiftR $(x) 7 |]
sigS 1 x = [| rotateR $(x) 19 `xor` rotateR $(x) 61 `xor` shiftR $(x) 6 |]
sigS _ _ = error "Wrong usage of sig function"
