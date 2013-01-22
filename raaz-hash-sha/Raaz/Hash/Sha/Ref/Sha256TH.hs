{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Ref.Sha256TH
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
                                      [| SHA256
                                         ($(subE' "a" (-1)) + $(subE' "a" 63))
                                         ($(subE' "b" (-1)) + $(subE' "b" 63))
                                         ($(subE' "c" (-1)) + $(subE' "c" 63))
                                         ($(subE' "d" (-1)) + $(subE' "d" 63))
                                         ($(subE' "e" (-1)) + $(subE' "e" 63))
                                         ($(subE' "f" (-1)) + $(subE' "f" 63))
                                         ($(subE' "g" (-1)) + $(subE' "g" 63))
                                         ($(subE' "h" (-1)) + $(subE' "h" 63))
                                      |])) []
    args1 = map (flip subP' (-1)) ["a","b","c","d","e","f","g","h"]
    args2 = map (subP' "m") [0..15]
    typeSig = sigD name $
              foldl (const . appT wordtype) (conT ''SHA256) [1..24 :: Int]
    wordtype = appT arrowT (conT ''Word32BE)
    subE' :: String -> Int -> ExpQ
    subE' = subE
    subP' :: String -> Int -> PatQ
    subP' = subP

-- | Unrolls the round loop. Also assumes
-- a__1,b__1,c__1,d__1,e__1,f__1,g__1,h__1 which are the hash values
-- in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = liftM2 (++) kdecs
              $ declarations [wdecs,adecs,edecs,restdecs] [0..63]
  where
    adecs :: Int -> DecsQ
    adecs = variable' "a" ''Word32BE body
      where
        body j = [| $(t1exp j) + $(t2exp j)
                 :: Word32BE |]

    edecs :: Int -> DecsQ
    edecs = variable' "e" ''Word32BE body
      where
        body j = [| $(subE "d" [j-1]) + $(t1exp j)
                 :: Word32BE |]

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
    wdecs = variable' "w" ''Word32BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| $(sigS 1 (subE "w" (j-2)))  +
                                $(subE "w" (j-7))           +
                                $(sigS 0 (subE "w" (j-15))) +
                                $(subE "w" (j-16))
                             :: Word32BE |]

    -- | The round constants for SHA1 hash
    kdecs :: DecsQ
    kdecs = constants "k" ''Word32BE
         [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1
         , 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
         , 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786
         , 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
         , 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147
         , 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
         , 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b
         , 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
         , 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a
         , 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
         , 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 :: Word32BE ]

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
