{-

This moduler contains helper template haskell functions which are
spliced in the actual module.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha1.Ref.TH
       ( oneRound
       ) where

import Control.Applicative
import Data.Bits
import Language.Haskell.TH

import Raaz.Types
import Raaz.Util.TH

import Raaz.Hash.Sha1.Type(SHA1(..))

-- | Declares roundF function which denotes compression of one
-- block. This is used internally for efficient code generation using
-- Template Haskell.
oneRound :: DecsQ
oneRound = sequence $ [typeSig, funD name [cls]]
  where
    name = mkName "roundF"
    cls = clause (args1:args2) (normalB (LetE <$> roundLoop <*>
                                      [| addHash $(s $ -1) $(s $ 79) |])) []
    args1 = subP "s" $ (-1 :: Int)
    args2 = map (subP "m") [0..15 :: Int]
    typeSig = sigD name $ appT (appT arrowT (conT ''SHA1)) $
                foldl (const . appT wordtype) (conT ''SHA1) [1..16 :: Int]
    wordtype = appT arrowT (conT ''Word32BE)

-- | Unrolls the round loop.  Also assumes s__1 which is the hash
-- value in the previous round also present in scope.
roundLoop :: DecsQ
roundLoop = declarations [wDecs,kDecs,transDecs] [0..79]
  where
    transDecs = variable' "s" ''SHA1 body
      where
        body j = [| trans j $(s $ j-1) $(k $ j) $(w $ j) |]
    wDecs     = variable' "w" ''Word32BE body
      where
        body j | j<16      = subE "m" j
               | otherwise = [| rotateL ($(w $ j-3)  `xor` $(w $ j-8)  `xor`
                                         $(w $ j-14) `xor` $(w $ j-16)) 1 |]
    kDecs     = variable' "k" ''Word32BE body
      where
        body j  | j <= 19    = [| 0x5a827999 :: Word32BE |]
                | j <= 39    = [| 0x6ed9eba1 :: Word32BE |]
                | j <= 59    = [| 0x8f1bbcdc :: Word32BE |]
                | otherwise  = [| 0xca62c1d6 :: Word32BE |]

-- | The round functions
trans :: Int -> SHA1 -> Word32BE -> Word32BE -> SHA1
trans i (SHA1 a b c d e) k' w' | i <= 19 = SHA1 a' b' c' d' e'
  where a' = rotateL a 5 + ((b .&. c) `xor` (complement b .&. d)) + e + k' + w'
        b' = a
        c' = rotateL b 30
        d' = c
        e' = d
trans i (SHA1 a b c d e) k' w' | i <= 39 = SHA1 a' b' c' d' e'
  where a' = rotateL a 5 + (b `xor` c `xor` d) + e + k' + w'
        b' = a
        c' = rotateL b 30
        d' = c
        e' = d
trans i (SHA1 a b c d e) k' w' | i <= 59 = SHA1 a' b' c' d' e'
  where a' = rotateL a 5 + ((b .&. (c .|. d)) .|. (c .&. d)) + e + k' + w'
        b' = a
        c' = rotateL b 30
        d' = c
        e' = d
trans i (SHA1 a b c d e) k' w' | i <= 79 = SHA1 a' b' c' d' e'
  where a' = rotateL a 5 + (b `xor` c `xor` d) + e + k' + w'
        b' = a
        c' = rotateL b 30
        d' = c
        e' = d
trans _ _ _ _ = error "Wrong index used for trans"
{-# INLINE trans #-}

addHash :: SHA1 -> SHA1 -> SHA1
addHash (SHA1 a b c d e) (SHA1 a' b' c' d' e') =
  SHA1 (a+a') (b+b') (c+c') (d+d') (e+e')
{-# INLINE addHash #-}

k,s,w :: Int -> ExpQ
k = subE "k"
s = subE "s"
w = subE "w"
