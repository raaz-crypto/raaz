{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Ref.Sha1TH
       ( oneRound
       ) where

import Control.Applicative
import Data.Bits
import Language.Haskell.TH

import Raaz.Types
import Raaz.Util.TH

import Raaz.Hash.Sha.Types(SHA1(..))

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1 ++ args2) (normalB (LetE <$> roundLoop <*>
                                      [| SHA1
                                         ($(a $ -1) + $(a 79))
                                         ($(b $ -1) + $(b 79))
                                         ($(c $ -1) + $(c 79))
                                         ($(d $ -1) + $(d 79))
                                         ($(e $ -1) + $(e 79))
                                      |])) []
    args1 = map (flip subP (-1 :: Int)) ["a","b","c","d","e"]
    args2 = map (subP "m") [0..15 :: Int]
    typeSig = sigD name $
              foldl (const . appT wordtype) (conT ''SHA1) [1..21 :: Int]
    wordtype = appT arrowT (conT ''Word32BE)

-- | Unrolls the round loop.  Also assumes a__1,b__1,c__1,d__1,e__1,
-- which are the hash values in the previous round also present in
-- scope.
roundLoop :: DecsQ
roundLoop = declarations [wdecs,kdecs,adecs,cdecs,restdecs] [0..79]
  where
    adecs :: Int -> DecsQ
    adecs = variable' "a" ''Word32BE body
      where
        body j = [| $(r') + $(f') + $(e $ j-1) + $(k j) + $(w j) :: Word32BE |]
         where r' = [| rotateL $(a $ j-1) 5 |]
               f' = f j (b $ j-1) (c $ j-1) (d $ j-1)

    cdecs :: Int -> DecsQ
    cdecs = variable' "c" ''Word32BE body
      where
        body j = [| rotateL $(b $ j-1) 30 |]

    wdecs :: Int -> DecsQ
    wdecs = variable' "w" ''Word32BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| rotateL ($(w $ j-3)  `xor` $(w $ j-8)  `xor`
                                         $(w $ j-14) `xor` $(w $ j-16)) 1 |]

    kdecs :: Int -> DecsQ
    kdecs = variable' "k" ''Word32BE body
      where
        body j  | j <= 19    = [| 0x5a827999 :: Word32BE |]
                | j <= 39    = [| 0x6ed9eba1 :: Word32BE |]
                | j <= 59    = [| 0x8f1bbcdc :: Word32BE |]
                | otherwise  = [| 0xca62c1d6 :: Word32BE |]

    restdecs :: Int -> DecsQ
    restdecs = permute [("e","d"),("d","c"),("b","a")]

-- | The round functions
f :: Int -> ExpQ -> ExpQ -> ExpQ -> ExpQ
f i x y z | i <= 19   = [| ($(x) .&. $(y)) `xor` (complement $(x) .&. $(z)) |]
          | i <= 39   = [| $(x) `xor` $(y) `xor` $(z) |]
          | i <= 59   = [| ($(x) .&. $(y)) `xor` ($(y) .&. $(z)) `xor` ($(z)
                           .&. $(x)) |]
          | otherwise = [| $(x) `xor` $(y) `xor` $(z) |]

a,b,c,d,e,k,w :: Int -> ExpQ
a = subE "a"
b = subE "b"
c = subE "c"
d = subE "d"
e = subE "e"
k = subE "k"
w = subE "w"
