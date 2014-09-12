{-|

This module gives the reference implementation of the Blake256
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE BangPatterns, OverloadedStrings #-}

module Raaz.Hash.Blake256.Ref
       ( blake256CompressSingle
       ) where

import Control.Applicative
import Data.Bits
import Data.ByteString         (ByteString)
import Data.ByteString.Char8   ()
import Data.ByteString.Unsafe  (unsafeIndex)
import Data.Word
import Numeric                 ()

import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Blake256.Type

-- | This gives the 10 permutation of {0,...,15} used by Blake functions.
table :: ByteString
table = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\
        \\xe\xa\x4\x8\x9\xf\xd\x6\x1\xc\x0\x2\xb\x7\x5\x3\
        \\xb\x8\xc\x0\x5\x2\xf\xd\xa\xe\x3\x6\x7\x1\x9\x4\
        \\x7\x9\x3\x1\xd\xc\xb\xe\x2\x6\x5\xa\x4\x0\xf\x8\
        \\x9\x0\x5\x7\x2\x4\xa\xf\xe\x1\xb\xc\x6\x8\x3\xd\
        \\x2\xc\x6\xa\x0\xb\x8\x3\x4\xd\x7\x5\xf\xe\x1\x9\
        \\xc\x5\x1\xf\xe\xd\x4\xa\x0\x7\x6\x3\x9\x2\x8\xb\
        \\xd\xb\x7\xe\xc\x1\x3\x9\x5\x0\xf\x4\x8\x6\x2\xa\
        \\x6\xf\xe\x9\xb\x3\x0\x8\xc\x2\xd\x7\x1\x4\xa\x5\
        \\xa\x2\x8\x4\x7\x6\x1\x5\xf\xb\x9\xe\x3\xc\xd\x0"

sigma :: Int -> Int -> Int
sigma i j = fromEnum $ unsafeIndex table (i*16 + j)

-- | The sixteen constants of BLAKE-256
lookUpC :: Int -> BE Word32
lookUpC 0  = 0x243F6A88
lookUpC 1  = 0x85A308D3
lookUpC 2  = 0x13198A2E
lookUpC 3  = 0x03707344
lookUpC 4  = 0xA4093822
lookUpC 5  = 0x299F31D0
lookUpC 6  = 0x082EFA98
lookUpC 7  = 0xEC4E6C89
lookUpC 8  = 0x452821E6
lookUpC 9  = 0x38D01377
lookUpC 10 = 0xBE5466CF
lookUpC 11 = 0x34E90C6C
lookUpC 12 = 0xC0AC29B7
lookUpC 13 = 0xC97C50DD
lookUpC 14 = 0x3F84D5B5
lookUpC 15 = 0xB5470917
lookUpC _  = error "Wrong input to lookUpC function"

-- | State is 4 word pair on which roundG function is applied
type State  = (BE Word32, BE Word32, BE Word32, BE Word32)

-- | Matrix is 16 word pair on which the Diagonal and Column steps are applied
type Matrix = (State, State, State, State)

-- Compress function
compress :: BLAKE256
         -> Salt
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BE Word32
         -> BLAKE256
compress b@(BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7)
         s@(Salt s0 s1 s2 s3)
         !t0  !t1
         !m0  !m1  !m2  !m3
         !m4  !m5  !m6  !m7
         !m8  !m9  !m10 !m11
         !m12 !m13 !m14 !m15 = BLAKE256 h0' h1' h2' h3' h4' h5' h6' h7'
           where
             initial = initialState b s t0 t1
             (  (v0,  v1,  v2,  v3)
              , (v4,  v5,  v6,  v7)
              , (v8,  v9,  v10, v11)
              , (v12, v13, v14, v15)
              ) = foldl (roundHash m0  m1  m2  m3
                                   m4  m5  m6  m7
                                   m8  m9  m10 m11
                                   m12 m13 m14 m15) initial [0..13]
             !h0' = h0 `xor` s0 `xor` v0 `xor` v8
             !h1' = h1 `xor` s1 `xor` v1 `xor` v9
             !h2' = h2 `xor` s2 `xor` v2 `xor` v10
             !h3' = h3 `xor` s3 `xor` v3 `xor` v11
             !h4' = h4 `xor` s0 `xor` v4 `xor` v12
             !h5' = h5 `xor` s1 `xor` v5 `xor` v13
             !h6' = h6 `xor` s2 `xor` v6 `xor` v14
             !h7' = h7 `xor` s3 `xor` v7 `xor` v15

-- | Single Round Function of Blake256
roundG :: State
       -> BE Word32
       -> BE Word32
       -> BE Word32
       -> BE Word32
       -> State
roundG (a, b, c, d) !m0' !m1' !c0' !c1' = (a', b', c', d')
  where
    !a0 = a + b + (m0' `xor` c1')
    !d0 = (d `xor` a0) `rotateR` 16
    !c0 = c + d0
    !b0 = (b `xor` c0) `rotateR` 12
    !a' = a0 + b0 + (m1' `xor` c0')
    !d' = (d0 `xor` a') `rotateR` 8
    !c' = c0 + d'
    !b' = (b0 `xor` c') `rotateR` 7

roundHash :: BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> BE Word32
          -> Matrix    -- Given Matrix
          -> Int       -- Round number
          -> Matrix
roundHash m0  m1  m2  m3
          m4  m5  m6  m7
          m8  m9  m10 m11
          m12 m13 m14 m15
          ( (v0,  v1,  v2,  v3)
          , (v4,  v5,  v6,  v7)
          , (v8,  v9,  v10, v11)
          , (v12, v13, v14, v15)
          )
          rnd  =
  let
    lookUpMessage 0  = m0
    lookUpMessage 1  = m1
    lookUpMessage 2  = m2
    lookUpMessage 3  = m3
    lookUpMessage 4  = m4
    lookUpMessage 5  = m5
    lookUpMessage 6  = m6
    lookUpMessage 7  = m7
    lookUpMessage 8  = m8
    lookUpMessage 9  = m9
    lookUpMessage 10 = m10
    lookUpMessage 11 = m11
    lookUpMessage 12 = m12
    lookUpMessage 13 = m13
    lookUpMessage 14 = m14
    lookUpMessage 15 = m15
    lookUpMessage _  = error "Wrong input to lookUpMessage function"

    -- Perform roundG function to one given state
    g (i, fourVariable) = roundG fourVariable
                                 (lookUpMessage $ sigma r2 i2)
                                 (lookUpMessage $ sigma r2 i3)
                                 (lookUpC $ sigma r2 i2)
                                 (lookUpC $ sigma r2 i3)
                            where
                              !r2 = rnd `mod` 10
                              !i2 = i * 2
                              !i3 = i2 + 1

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
    applyColumns _ = error "Error in applyColumns"

    -- Apply G to diagonals
    applyDiagonals [ (c00,c01,c02,c03)
                   , (c10,c11,c12,c13)
                   , (c20,c21,c22,c23)
                   , (c30,c31,c32,c33)
                   ] = map g [ (4,(c00, c11, c22, c33))    -- Mapping g
                             , (5,(c10, c21, c32, c03))
                             , (6,(c20, c31, c02, c13))
                             , (7,(c30, c01, c12, c23))
                             ]
    applyDiagonals _ = error "Error in applyDiagonals"

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
    finalising _ = error "Error in finalising"
  in
    finalising $ applyDiagonals $ applyColumns [ v0,  v1,  v2,  v3
                                               , v4,  v5,  v6,  v7
                                               , v8,  v9,  v10 ,v11
                                               , v12, v13, v14 ,v15
                                               ]

-- | Returns initial 16 word state
initialState :: BLAKE256
             -> Salt
             -> BE Word32
             -> BE Word32
             -> Matrix

initialState (BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7)
             (Salt s0 s1 s2 s3)
             t0 t1 =  ( (h0, h1, h2, h3)
                      , (h4, h5, h6, h7)
                      , ( s0 `xor` (lookUpC 0)
                        , s1 `xor` (lookUpC 1)
                        , s2 `xor` (lookUpC 2)
                        , s3 `xor` (lookUpC 3)
                        )
                      , ( t0 `xor` (lookUpC 4)
                        , t0 `xor` (lookUpC 5)
                        , t1 `xor` (lookUpC 6)
                        , t1 `xor` (lookUpC 7)
                        )
                      )


-- | Compresses one block.
blake256CompressSingle :: BLAKE256
                       -> Salt
                       -> BITS Word64
                       -> CryptoPtr
                       -> IO BLAKE256
blake256CompressSingle blake256 s t cptr = compress blake256 s t0 t1
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
