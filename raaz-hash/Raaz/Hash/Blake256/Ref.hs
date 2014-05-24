{-|

This module gives the reference implementation of the Blake256
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Blake256.Ref
       ( blake256CompressSingle
       ) where

import Control.Applicative

import Raaz.Types
import Raaz.Util.Ptr
import Data.Bits
import Data.Word
import Numeric

import Raaz.Hash.Blake256.Type

sigma :: Int -> Int -> Int
sigma 0 0 = 0
sigma 0 1 = 1
sigma 0 2 = 2
sigma 0 3 = 3
sigma 0 4 = 4
sigma 0 5 = 5
sigma 0 6 = 6
sigma 0 7 = 7
sigma 0 8 = 8
sigma 0 9 = 9
sigma 0 10 = 10
sigma 0 11 = 11
sigma 0 12 = 12
sigma 0 13 = 13
sigma 0 14 = 14
sigma 0 15 = 15


sigma 1 0 = 14
sigma 1 1 = 10
sigma 1 2 = 4
sigma 1 3 = 8
sigma 1 4 = 9
sigma 1 5 = 15
sigma 1 6 = 13
sigma 1 7 = 6
sigma 1 8 = 1
sigma 1 9 = 12
sigma 1 10 = 0
sigma 1 11 = 2
sigma 1 12 = 11
sigma 1 13 = 7
sigma 1 14 = 5
sigma 1 15 = 3

sigma 2 0 = 11
sigma 2 1 = 8
sigma 2 2 = 12
sigma 2 3 = 0
sigma 2 4 = 5
sigma 2 5 = 2
sigma 2 6 = 15
sigma 2 7 = 13
sigma 2 8 = 10
sigma 2 9 = 14
sigma 2 10 = 3
sigma 2 11 = 6
sigma 2 12 = 7
sigma 2 13 = 1
sigma 2 14 = 9
sigma 2 15 = 4

sigma 3 0 = 7
sigma 3 1 = 9
sigma 3 2 = 3
sigma 3 3 = 1
sigma 3 4 = 13
sigma 3 5 = 12
sigma 3 6 = 11
sigma 3 7 = 14
sigma 3 8 = 2
sigma 3 9 = 6
sigma 3 10 = 5
sigma 3 11 = 10
sigma 3 12 = 4
sigma 3 13 = 0
sigma 3 14 = 15
sigma 3 15 = 8

sigma 4 0 = 9
sigma 4 1 = 0
sigma 4 2 = 5
sigma 4 3 = 7
sigma 4 4 = 2
sigma 4 5 = 4
sigma 4 6 = 10
sigma 4 7 = 15
sigma 4 8 = 14
sigma 4 9 = 1
sigma 4 10 = 11
sigma 4 11 = 12
sigma 4 12 = 6
sigma 4 13 = 8
sigma 4 14 = 3
sigma 4 15 = 13

sigma 5 0 = 2
sigma 5 1 = 12
sigma 5 2 = 6
sigma 5 3 = 10
sigma 5 4 = 0
sigma 5 5 = 11
sigma 5 6 = 8
sigma 5 7 = 3
sigma 5 8 = 4
sigma 5 9 = 13
sigma 5 10 = 7
sigma 5 11 = 5
sigma 5 12 = 15
sigma 5 13 = 14
sigma 5 14 = 1
sigma 5 15 = 9

sigma 6 0 = 12
sigma 6 1 = 5
sigma 6 2 = 1
sigma 6 3 = 15
sigma 6 4 = 14
sigma 6 5 = 13
sigma 6 6 = 4
sigma 6 7 = 10
sigma 6 8 = 0
sigma 6 9 = 7
sigma 6 10 = 6
sigma 6 11 = 3
sigma 6 12 = 9
sigma 6 13 = 2
sigma 6 14 = 8
sigma 6 15 = 11

sigma 7 0 = 13
sigma 7 1 = 11
sigma 7 2 = 7
sigma 7 3 = 14
sigma 7 4 = 12
sigma 7 5 = 1
sigma 7 6 = 3
sigma 7 7 = 9
sigma 7 8 = 5
sigma 7 9 = 0
sigma 7 10 = 15
sigma 7 11 = 4
sigma 7 12 = 8
sigma 7 13 = 6
sigma 7 14 = 2
sigma 7 15 = 10

sigma 8 0 = 6
sigma 8 1 = 15
sigma 8 2 = 14
sigma 8 3 = 9
sigma 8 4 = 11
sigma 8 5 = 3
sigma 8 6 = 0
sigma 8 7 = 8
sigma 8 8 = 12
sigma 8 9 = 2
sigma 8 10 = 13
sigma 8 11 = 7
sigma 8 12 = 1
sigma 8 13 = 4
sigma 8 14 = 10
sigma 8 15 = 5

sigma 9 0 = 10
sigma 9 1 = 2
sigma 9 2 = 8
sigma 9 3 = 4
sigma 9 4 = 7
sigma 9 5 = 6
sigma 9 6 = 1
sigma 9 7 = 5
sigma 9 8 = 15
sigma 9 9 = 11
sigma 9 10 = 9
sigma 9 11 = 14
sigma 9 12 = 3
sigma 9 13 = 12
sigma 9 14 = 13
sigma 9 15 = 0

lookUpC :: Int -> Word32BE
lookUpC 0 = 0x243F6A88
lookUpC 1 = 0x85A308D3
lookUpC 2 = 0x13198A2E
lookUpC 3 = 0x03707344
lookUpC 4 = 0xA4093822
lookUpC 5 = 0x299F31D0
lookUpC 6 = 0x082EFA98
lookUpC 7 = 0xEC4E6C89
lookUpC 8 = 0x452821E6
lookUpC 9 = 0x38D01377
lookUpC 10 = 0xBE5466CF
lookUpC 11 = 0x34E90C6C
lookUpC 12 = 0xC0AC29B7
lookUpC 13 = 0xC97C50DD
lookUpC 14 = 0x3F84D5B5
lookUpC 15 = 0xB5470917

type State  = (Word32BE, Word32BE, Word32BE, Word32BE)
type Matrix = (State, State, State, State)

compress :: BLAKE256
         -> Salt 
         -> Word32BE
         -> Word32BE    
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> Word32BE 
         -> BLAKE256
compress b@(BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7) 
         s@(Salt s0 s1 s2 s3)
         t0 t1 
         m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15 =  
            BLAKE256 h0' h1' h2' h3' h4' h5' h6' h7'
            where 
                rounds = 14  -- 14 rounds for BLAKE256

                initial = initialState b s t0 t1

                ((v0, v1, v2, v3), (v4, v5, v6, v7), (v8, v9, v10, v11), (v12, v13, v14, v15)) = 
                    foldl 
                    (roundHash m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15)
                    initial  
                    [0..rounds-1]

                h0' = h0 `xor` s0 `xor` v0 `xor` v8
                h1' = h1 `xor` s1 `xor` v1 `xor` v9
                h2' = h2 `xor` s2 `xor` v2 `xor` v10
                h3' = h3 `xor` s3 `xor` v3 `xor` v11
                h4' = h4 `xor` s0 `xor` v4 `xor` v12
                h5' = h5 `xor` s1 `xor` v5 `xor` v13
                h6' = h6 `xor` s2 `xor` v6 `xor` v14
                h7' = h7 `xor` s3 `xor` v7 `xor` v15


    
-- One Round function G applied.
roundG :: State 
          -> Word32BE 
          -> Word32BE 
          -> Word32BE 
          -> Word32BE 
          -> State
roundG (a, b, c, d) m0' m1' c0' c1' = (a', b', c', d')
    where 
        a0 = a + b + (m0' `xor` c1') 
        d0 = (d `xor` a0) `rotateR` 16
        c0 = c + d0
        b0 = (b `xor` c0) `rotateR` 12
        a' = a0 + b0 + (m1' `xor` c0')
        d' = (d0 `xor` a') `rotateR` 8
        c' = c0 + d'
        b' = (b0 `xor` c') `rotateR` 7  



roundHash :: Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Word32BE 
             -> Matrix    -- Given Matrix
             -> Int       -- Round number
             -> Matrix
roundHash m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15
          ((v0, v1, v2 ,v3), (v4, v5, v6 ,v7), (v8, v9, v10 ,v11), (v12, v13, v14 ,v15))   
          rnd  =
    let
        lookUpMessage 0 = m0
        lookUpMessage 1 = m1
        lookUpMessage 2 = m2
        lookUpMessage 3 = m3
        lookUpMessage 4 = m4
        lookUpMessage 5 = m5
        lookUpMessage 6 = m6
        lookUpMessage 7 = m7
        lookUpMessage 8 = m8
        lookUpMessage 9 = m9
        lookUpMessage 10 = m10
        lookUpMessage 11 = m11
        lookUpMessage 12 = m12
        lookUpMessage 13 = m13
        lookUpMessage 14 = m14
        lookUpMessage 15 = m15

        -- Perform one function G
        g(i, fourVariable) = roundG fourVariable 
                                    (lookUpMessage (sigma (rnd `mod` 10) (2 * i)) )
                                    (lookUpMessage (sigma (rnd `mod` 10) ((2 * i) + 1)) )  
                                    (lookUpC (sigma (rnd `mod` 10) (2 * i)) )
                                    (lookUpC (sigma (rnd `mod` 10) ((2 * i) + 1)) )

        -- Apply G to columns
        applyColumns [ s0, s1, s2, s3
                     , s4, s5, s6, s7
                     , s8, s9,s10,s11
                     , s12,s13,s14,s15
                     ] = map g [ (0, (s0, s4, s8, s12))        -- Mapping g
                               , (1, (s1, s5, s9, s13))
                               , (2, (s2, s6, s10,s14))
                               , (3, (s3, s7, s11,s15))
                               ]

        -- Apply G to diagonals
        applyDiagonals [ (c00,c01,c02,c03)
                       , (c10,c11,c12,c13)
                       , (c20,c21,c22,c23)
                       , (c30,c31,c32,c33) 
                       ] = map g [(4,(c00, c11, c22, c33))
                                 ,(5,(c10, c21, c32, c03))
                                 ,(6,(c20, c31, c02, c13))
                                 ,(7,(c30, c01, c12, c23))
                                 ]

        -- Finalising
        finalising [ (d00,d01,d02,d03)
                   , (d10,d11,d12,d13)
                   , (d20,d21,d22,d23)
                   , (d30,d31,d32,d33)
                   ] = ( (d00,d10,d20,d30)
                       , (d31,d01,d11,d21)
                       , (d22,d32,d02,d12)
                       , (d13,d23,d33,d03)
                       )
    in
        finalising $ applyDiagonals $ applyColumns [v0, v1, v2 ,v3, v4, v5, v6 ,v7, v8, v9, v10 ,v11, v12, v13, v14 ,v15]

                       
-- initial 16 word state
initialState :: BLAKE256 
                -> Salt 
                -> Word32BE
                -> Word32BE
                -> Matrix

initialState (BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7) 
             (Salt s0 s1 s2 s3)
             t0 t1 =  ( (h0, h1, h2, h3)
                      , (h4, h5, h6, h7)
                      , (s0 `xor` (lookUpC 0), s1 `xor` (lookUpC 1), s2 `xor` (lookUpC 2), s3 `xor` (lookUpC 3) )
                      , (t0 `xor` (lookUpC 4), t0 `xor` (lookUpC 5), t1 `xor` (lookUpC 6), t1 `xor` (lookUpC 7) )
                      )

-- | Compresses one block.
blake256CompressSingle :: BLAKE256
                       -> Salt 
                       -> BITS Word64                           
                       -> CryptoPtr
                       -> IO BLAKE256
blake256CompressSingle blake256 s t cptr =
    compress blake256 s t0 t1
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
    where
        t' = fromIntegral t :: Word64
        t0 = fromIntegral t'
        t1 = fromIntegral (t' `shiftR` 32)
