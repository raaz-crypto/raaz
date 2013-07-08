{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha.Sha256.Ref.Sha256TH
       ( oneRound
       ) where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (liftM2)
import Data.Bits
import Language.Haskell.TH

import Raaz.Types
import Raaz.Util.TH

import Raaz.Hash.Sha.Sha256.Type(SHA256(..))

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1:args2) (normalB (LetE <$> roundLoop <*>
                                      [| addHash $(s $ -1) $(s $ 63) |])) []
    args1 = subP "s" (-1 :: Int)
    args2 = map (subP "m") [0..15 :: Int]
    typeSig = sigD name $ appT (appT arrowT (conT ''SHA256)) $
                foldl (const . appT wordtype) (conT ''SHA256) [1..16 :: Int]
    wordtype = appT arrowT (conT ''Word32BE)

-- | Unrolls the round loop. Also assumes s__1 which is the hash
-- values in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = liftM2 (++) kDecs $ declarations [transDecs,wDecs] [0..63]
  where
    transDecs :: Int -> DecsQ
    transDecs = variable' "s" ''SHA256 body
      where
        body j = [| trans $(s $ j-1) $(k $ j) $(w $ j) |]
    wDecs :: Int -> DecsQ
    wDecs = variable' "w" ''Word32BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| sigS1 $(w $ j-2) + $(w $ j-7) + sigS0 $(w $ j-15)
                              + $(w $ j-16) :: Word32BE |]
    kDecs :: DecsQ
    kDecs = constants "k" ''Word32BE
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

trans :: SHA256 -> Word32BE -> Word32BE -> SHA256
trans (SHA256 a b c d e f g h) k' w' = SHA256 a' b' c' d' e' f' g' h'
  where
    t1 = h + sigB1 e + ((e .&. f) `xor` (complement e .&. g)) + k' + w'
    t2 = sigB0 a + ((a .&. (b .|. c)) .|. (b .&. c))
    a' = t1 + t2
    b' = a
    c' = b
    d' = c
    e' = d + t1
    f' = e
    g' = f
    h' = g
{-# INLINE trans #-}

sigB0,sigB1,sigS0,sigS1 :: Word32BE -> Word32BE
sigB0 x = rotateR x 2  `xor` rotateR x 13 `xor` rotateR x 22
sigB1 x = rotateR x 6  `xor` rotateR x 11 `xor` rotateR x 25
sigS0 x = rotateR x 7  `xor` rotateR x 18 `xor` shiftR x 3
sigS1 x = rotateR x 17 `xor` rotateR x 19 `xor` shiftR x 10
{-# INLINE sigB0 #-}
{-# INLINE sigB1 #-}
{-# INLINE sigS0 #-}
{-# INLINE sigS1 #-}

addHash :: SHA256 -> SHA256 -> SHA256
addHash (SHA256 a b c d e f g h) (SHA256 a' b' c' d' e' f' g' h') =
  SHA256 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')
{-# INLINE addHash #-}

k,s,w :: Int -> ExpQ
k = subE "k"
s = subE "s"
w = subE "w"
