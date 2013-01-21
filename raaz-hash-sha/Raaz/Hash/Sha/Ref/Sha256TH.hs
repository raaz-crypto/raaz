{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Ref.Sha256TH
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
                                      [| SHA256
                                         ($(subE "a" [-1]) + $(subE "a" [63]))
                                         ($(subE "b" [-1]) + $(subE "b" [63]))
                                         ($(subE "c" [-1]) + $(subE "c" [63]))
                                         ($(subE "d" [-1]) + $(subE "d" [63]))
                                         ($(subE "e" [-1]) + $(subE "e" [63]))
                                         ($(subE "f" [-1]) + $(subE "f" [63]))
                                         ($(subE "g" [-1]) + $(subE "g" [63]))
                                         ($(subE "h" [-1]) + $(subE "h" [63]))
                                      |])) []
    args1 = map (flip subP [-1]) ["a","b","c","d","e","f","g","h"]
    args2 = map (\i -> subP "m" [i]) [0..15]
    typeSig = sigD name $
              foldl (const . appT wordtype) (conT ''SHA256) [1..24 :: Int]
    wordtype = appT arrowT (conT ''Word32BE)

-- | Unrolls the round loop. Also assumes
-- a__1,b__1,c__1,d__1,e__1,f__1,g__1,h__1 which are the hash values
-- in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = declarations [wdecs,kdecs,adecs,edecs,restdecs] [0..63]
  where
    adecs :: Int -> DecsQ
    adecs i = variable' "a" ''Word32BE body [i]
      where
        body [j] = [| $(t1exp j) + $(t2exp j)
                   :: Word32BE |]
        body _   = error "Unimaginable happended"

    edecs :: Int -> DecsQ
    edecs i = variable' "e" ''Word32BE body [i]
      where
        body [j] = [| $(subE "d" [j-1]) + $(t1exp j)
                   :: Word32BE |]
        body _   = error "Unimaginable happended"

    t1exp :: Int -> ExpQ
    t1exp j = [| $(subE "h" [j-1])
               + $(sigB 1 (subE "e" [j-1]))
               + $(ch (subE "e" [j-1]) (subE "f" [j-1]) (subE "g" [j-1]))
               + $(subE "k" [j])
               + $(subE "w" [j])
               :: Word32BE |]

    t2exp :: Int -> ExpQ
    t2exp j = [| $(sigB 0 (subE "a" [j-1]))
               + $(maj (subE "a" [j-1]) (subE "b" [j-1]) (subE "c" [j-1]))
               :: Word32BE |]


    wdecs :: Int -> DecsQ
    wdecs i = variable' "w" ''Word32BE body [i]
      where
        body [j] | i<16      = subE "m" [j]
                 | otherwise = [| $(sigS 1 (subE "w" [j-2]))  +
                                  $(subE "w" [j-7])           +
                                  $(sigS 0 (subE "w" [j-15])) +
                                  $(subE "w" [j-16])
                                :: Word32BE |]
        body _   = error "Unimaginable happended"

    -- | The round constants for SHA1 hash
    kdecs :: Int -> DecsQ
    kdecs i = variable' "k" ''Word32BE body [i]
      where
        body [0]  = [| 0x428a2f98 :: Word32BE |]
        body [1]  = [| 0x71374491 :: Word32BE |]
        body [2]  = [| 0xb5c0fbcf :: Word32BE |]
        body [3]  = [| 0xe9b5dba5 :: Word32BE |]
        body [4]  = [| 0x3956c25b :: Word32BE |]
        body [5]  = [| 0x59f111f1 :: Word32BE |]
        body [6]  = [| 0x923f82a4 :: Word32BE |]
        body [7]  = [| 0xab1c5ed5 :: Word32BE |]
        body [8]  = [| 0xd807aa98 :: Word32BE |]
        body [9]  = [| 0x12835b01 :: Word32BE |]
        body [10] = [| 0x243185be :: Word32BE |]
        body [11] = [| 0x550c7dc3 :: Word32BE |]
        body [12] = [| 0x72be5d74 :: Word32BE |]
        body [13] = [| 0x80deb1fe :: Word32BE |]
        body [14] = [| 0x9bdc06a7 :: Word32BE |]
        body [15] = [| 0xc19bf174 :: Word32BE |]
        body [16] = [| 0xe49b69c1 :: Word32BE |]
        body [17] = [| 0xefbe4786 :: Word32BE |]
        body [18] = [| 0x0fc19dc6 :: Word32BE |]
        body [19] = [| 0x240ca1cc :: Word32BE |]
        body [20] = [| 0x2de92c6f :: Word32BE |]
        body [21] = [| 0x4a7484aa :: Word32BE |]
        body [22] = [| 0x5cb0a9dc :: Word32BE |]
        body [23] = [| 0x76f988da :: Word32BE |]
        body [24] = [| 0x983e5152 :: Word32BE |]
        body [25] = [| 0xa831c66d :: Word32BE |]
        body [26] = [| 0xb00327c8 :: Word32BE |]
        body [27] = [| 0xbf597fc7 :: Word32BE |]
        body [28] = [| 0xc6e00bf3 :: Word32BE |]
        body [29] = [| 0xd5a79147 :: Word32BE |]
        body [30] = [| 0x06ca6351 :: Word32BE |]
        body [31] = [| 0x14292967 :: Word32BE |]
        body [32] = [| 0x27b70a85 :: Word32BE |]
        body [33] = [| 0x2e1b2138 :: Word32BE |]
        body [34] = [| 0x4d2c6dfc :: Word32BE |]
        body [35] = [| 0x53380d13 :: Word32BE |]
        body [36] = [| 0x650a7354 :: Word32BE |]
        body [37] = [| 0x766a0abb :: Word32BE |]
        body [38] = [| 0x81c2c92e :: Word32BE |]
        body [39] = [| 0x92722c85 :: Word32BE |]
        body [40] = [| 0xa2bfe8a1 :: Word32BE |]
        body [41] = [| 0xa81a664b :: Word32BE |]
        body [42] = [| 0xc24b8b70 :: Word32BE |]
        body [43] = [| 0xc76c51a3 :: Word32BE |]
        body [44] = [| 0xd192e819 :: Word32BE |]
        body [45] = [| 0xd6990624 :: Word32BE |]
        body [46] = [| 0xf40e3585 :: Word32BE |]
        body [47] = [| 0x106aa070 :: Word32BE |]
        body [48] = [| 0x19a4c116 :: Word32BE |]
        body [49] = [| 0x1e376c08 :: Word32BE |]
        body [50] = [| 0x2748774c :: Word32BE |]
        body [51] = [| 0x34b0bcb5 :: Word32BE |]
        body [52] = [| 0x391c0cb3 :: Word32BE |]
        body [53] = [| 0x4ed8aa4a :: Word32BE |]
        body [54] = [| 0x5b9cca4f :: Word32BE |]
        body [55] = [| 0x682e6ff3 :: Word32BE |]
        body [56] = [| 0x748f82ee :: Word32BE |]
        body [57] = [| 0x78a5636f :: Word32BE |]
        body [58] = [| 0x84c87814 :: Word32BE |]
        body [59] = [| 0x8cc70208 :: Word32BE |]
        body [60] = [| 0x90befffa :: Word32BE |]
        body [61] = [| 0xa4506ceb :: Word32BE |]
        body [62] = [| 0xbef9a3f7 :: Word32BE |]
        body [63] = [| 0xc67178f2 :: Word32BE |]
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
sigB 0 x = [| rotateR $(x) 2 `xor` rotateR $(x) 13 `xor` rotateR $(x) 22 |]
sigB 1 x = [| rotateR $(x) 6 `xor` rotateR $(x) 11 `xor` rotateR $(x) 25 |]
sigB _ _ = error "Wrong usage of sig function"

sigS :: Int -> ExpQ -> ExpQ
sigS 0 x = [| rotateR $(x) 7  `xor` rotateR $(x) 18 `xor` shiftR $(x) 3 |]
sigS 1 x = [| rotateR $(x) 17 `xor` rotateR $(x) 19 `xor` shiftR $(x) 10 |]
sigS _ _ = error "Wrong usage of sig function"
