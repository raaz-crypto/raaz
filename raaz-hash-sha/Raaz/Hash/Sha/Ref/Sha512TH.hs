{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Ref.Sha512TH
       ( oneRound
       ) where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (liftM2)
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
                                         ($(subE' "a" (-1)) + $(subE' "a" 79))
                                         ($(subE' "b" (-1)) + $(subE' "b" 79))
                                         ($(subE' "c" (-1)) + $(subE' "c" 79))
                                         ($(subE' "d" (-1)) + $(subE' "d" 79))
                                         ($(subE' "e" (-1)) + $(subE' "e" 79))
                                         ($(subE' "f" (-1)) + $(subE' "f" 79))
                                         ($(subE' "g" (-1)) + $(subE' "g" 79))
                                         ($(subE' "h" (-1)) + $(subE' "h" 79))
                                      |])) []
    args1 = map (flip subP' (-1)) ["a","b","c","d","e","f","g","h"]
    args2 = map (subP' "m") [0..15]
    typeSig = sigD name $
              foldl (const . appT wordtype) (conT ''SHA512) [1..24 :: Int]
    wordtype = appT arrowT (conT ''Word64BE)
    subE' :: String -> Int -> ExpQ
    subE' = subE
    subP' :: String -> Int -> PatQ
    subP' = subP

-- | Unrolls the round loop. Also assumes
-- a__1,b__1,c__1,d__1,e__1,f__1,g__1,h__1 which are the hash values
-- in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = liftM2 (++) kdecs
               $ declarations [wdecs,adecs,edecs,restdecs] [0..79]
  where
    adecs :: Int -> DecsQ
    adecs = variable' "a" ''Word64BE body
      where
        body j = [| $(t1exp j) + $(t2exp j)
                 :: Word64BE |]

    edecs :: Int -> DecsQ
    edecs = variable' "e" ''Word64BE body
      where
        body j = [| $(subE "d" $ j-1) + $(t1exp j)
                 :: Word64BE |]

    t1exp :: Int -> ExpQ
    t1exp j = [| $(subE "h" (j-1))
               + $(sigB 1 (subE "e" (j-1)))
               + $(ch (subE "e" $ j-1) (subE "f" $ j-1) (subE "g" $ j-1))
               + $(subE "k" j)
               + $(subE "w" j)
              :: Word64BE |]

    t2exp :: Int -> ExpQ
    t2exp j = [| $(sigB 0 (subE "a" $ j-1))
               + $(maj (subE "a" $ j-1) (subE "b" $ j-1) (subE "c" $ j-1))
              :: Word64BE |]


    wdecs :: Int -> DecsQ
    wdecs = variable' "w" ''Word64BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| $(sigS 1 (subE "w" $ j-2))  +
                                $(subE "w" $ j-7)           +
                                $(sigS 0 (subE "w" $ j-15)) +
                                $(subE "w" $ j-16)
                             :: Word64BE |]

    -- | The round constants for SHA1 hash
    kdecs :: DecsQ
    kdecs = constants "k" ''Word64BE
                [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f
                , 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019
                , 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242
                , 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
                , 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235
                , 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
                , 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275
                , 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
                , 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f
                , 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
                , 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc
                , 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
                , 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6
                , 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001
                , 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218
                , 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
                , 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99
                , 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
                , 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc
                , 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
                , 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915
                , 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207
                , 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba
                , 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
                , 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc
                , 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
                , 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 :: Word64BE]

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
