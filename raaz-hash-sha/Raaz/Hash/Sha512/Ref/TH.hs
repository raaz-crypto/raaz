{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha512.Ref.TH
       ( oneRound
       ) where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (liftM2)
import Data.Bits
import Language.Haskell.TH

import Raaz.Types
import Raaz.Util.TH

import Raaz.Hash.Sha512.Type(SHA512(..))

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1:args2) (normalB (LetE <$> roundLoop <*>
                                      [| addHash $(s $ -1) $(s $ 79) |])) []
    args1 = subP "s" (-1 :: Int)
    args2 = map (subP "m") [0..15 :: Int]
    typeSig = sigD name $ appT (appT arrowT (conT ''SHA512)) $
                foldl (const . appT wordtype) (conT ''SHA512) [1..16 :: Int]
    wordtype = appT arrowT (conT ''Word64BE)

-- | Unrolls the round loop. Also assumes s__1 which is the hash value
-- in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = liftM2 (++) kDecs $ declarations [transDecs,wDecs] [0..79]
  where
    transDecs :: Int -> DecsQ
    transDecs = variable' "s" ''SHA512 body
      where
        body j = [| trans $(s $ j-1) $(k $ j) $(w $ j) |]
    wDecs :: Int -> DecsQ
    wDecs = variable' "w" ''Word64BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| sigS1 $(w $ j-2) + $(w $ j-7) + sigS0 $(w $ j-15)
                              + $(w $ j-16) :: Word64BE |]
    kDecs :: DecsQ
    kDecs = constants "k" ''Word64BE
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

trans :: SHA512 -> Word64BE -> Word64BE -> SHA512
trans (SHA512 a b c d e f g h) k' w' = SHA512 a' b' c' d' e' f' g' h'
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

sigB0,sigB1,sigS0,sigS1 :: Word64BE -> Word64BE
sigB0 x = rotateR x 28 `xor` rotateR x 34 `xor` rotateR x 39
sigB1 x = rotateR x 14 `xor` rotateR x 18 `xor` rotateR x 41
sigS0 x = rotateR x 1  `xor` rotateR x 8  `xor` shiftR  x 7
sigS1 x = rotateR x 19 `xor` rotateR x 61 `xor` shiftR  x 6
{-# INLINE sigB0 #-}
{-# INLINE sigB1 #-}
{-# INLINE sigS0 #-}
{-# INLINE sigS1 #-}

addHash :: SHA512 -> SHA512 -> SHA512
addHash (SHA512 a b c d e f g h) (SHA512 a' b' c' d' e' f' g' h') =
  SHA512 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')
{-# INLINE addHash #-}

k,s,w :: Int -> ExpQ
k = subE "k"
s = subE "s"
w = subE "w"
