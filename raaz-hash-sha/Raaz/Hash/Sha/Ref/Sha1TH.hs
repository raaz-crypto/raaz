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

import Raaz.Hash.Sha

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1 ++ args2) (normalB (LetE <$> roundLoop <*>
                                      [| SHA1
                                         ($(subE "a" [-1]) + $(subE "a" [79]))
                                         ($(subE "b" [-1]) + $(subE "b" [79]))
                                         ($(subE "c" [-1]) + $(subE "c" [79]))
                                         ($(subE "d" [-1]) + $(subE "d" [79]))
                                         ($(subE "e" [-1]) + $(subE "e" [79]))
                                      |])) []
    args1 = map (flip subP [-1]) ["a","b","c","d","e"]
    args2 = map (\i -> subP "m" [i]) [0..15]
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
    adecs i = variable' "a" ''Word32BE body [i]
      where
        body [j] = [|   $([| rotateL $(subE "a" [j-1]) 5 |]) -- ROTL5(a)
                      + $(f j (subE "b" [j-1])           -- f (i-1) b_(i-1)
                                  (subE "c" [j-1])           -- c_(i-1)
                                  (subE "d" [j-1]) )         -- d_(i-1)
                      + $(subE "e" [j-1])                    -- e_(i-1)
                      + $(subE "k" [j])                      -- k (i-1)
                      + $(subE "w" [j])                      -- w_(i-1)
                      :: Word32BE |]
        body _   = error "Unimaginable happended"

    cdecs :: Int -> DecsQ
    cdecs i = variable' "c" ''Word32BE body [i]
      where
        body [j] = [| rotateL $(subE "b" [j-1]) 30|]
        body _   = error "Unimaginable happended"

    wdecs :: Int -> DecsQ
    wdecs i = variable' "w" ''Word32BE body [i]
      where
        body [j] | i<16      = subE "m" [j]
                 | otherwise = [| rotateL ( $(subE "w" [j-3])  `xor`
                                            $(subE "w" [j-8])  `xor`
                                            $(subE "w" [j-14]) `xor`
                                            $(subE "w" [j-16])
                                          ) 1 |]
        body _   = error "Unimaginable happended"

    -- | The round constants for SHA1 hash
    kdecs :: Int -> DecsQ
    kdecs i = variable' "k" ''Word32BE body [i]
      where
        body [_] | i <= 19    = [| 0x5a827999 :: Word32BE |]
                 | i <= 39    = [| 0x6ed9eba1 :: Word32BE |]
                 | i <= 59    = [| 0x8f1bbcdc :: Word32BE |]
                 | otherwise = [| 0xca62c1d6 :: Word32BE |]
        body _   = error "Unimaginable happended"

    restdecs :: Int -> DecsQ
    restdecs = permute [("e","d"),("d","c"),("b","a")]

-- | The round functions
f :: Int -> ExpQ -> ExpQ -> ExpQ -> ExpQ
f i x y z | i <= 19   = [| ($(x) .&. $(y)) `xor` (complement $(x) .&. $(z)) |]
          | i <= 39   = [| $(x) `xor` $(y) `xor` $(z) |]
          | i <= 59   = [| ($(x) .&. $(y)) `xor` ($(y) .&. $(z)) `xor` ($(z)
                           .&. $(x)) |]
          | i <= 79   = [| $(x) `xor` $(y) `xor` $(z) |]
          | otherwise = error "unthinkable has happened f_t in SHA1 reference"
