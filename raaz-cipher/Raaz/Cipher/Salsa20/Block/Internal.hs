module Raaz.Cipher.Salsa20.Block.Internal where

import           Data.List                            (foldl')
import           Data.Bits
import           Raaz.Cipher.Salsa20.Block.Type

quarterRound :: STATE -> STATE
quarterRound (STATE y0 y1 y2 y3) = STATE z0 z1 z2 z3
  where
    z1 = y1 `xor` ((y0 + y3) `rotateL` 7)
    z2 = y2 `xor` ((z1 + y0) `rotateL` 9)
    z3 = y3 `xor` ((z2 + z1) `rotateL` 13)
    z0 = y0 `xor` ((z3 + z2) `rotateL` 18)
{-# INLINE quarterRound #-}

rotateStateL :: STATE -> Int -> STATE
rotateStateL s                   0 = s
rotateStateL (STATE s0 s1 s2 s3) 1 = STATE s1 s2 s3 s0
rotateStateL (STATE s0 s1 s2 s3) 2 = STATE s2 s3 s0 s1
rotateStateL (STATE s0 s1 s2 s3) 3 = STATE s3 s0 s1 s2
rotateStateL s                   n = rotateStateL s (n-4)
{-# INLINE rotateStateL #-}

rowRound :: Matrix -> Matrix
rowRound (Matrix s0 s1 s2 s3) =
  Matrix (quarterRound s0)
         ((quarterRound (s1 `rotateStateL` 1)) `rotateStateL` 3)
         ((quarterRound (s2 `rotateStateL` 2)) `rotateStateL` 2)
         ((quarterRound (s3 `rotateStateL` 3)) `rotateStateL` 1)
{-# INLINE rowRound #-}

colRound :: Matrix -> Matrix
colRound = transposeMatrix . rowRound . transposeMatrix
{-# INLINE colRound #-}

doubleRound :: Matrix -> Matrix
doubleRound = rowRound . colRound
{-# INLINE doubleRound #-}

-- | Performs given number of rounds of salsa20. Typical rounds are 20
-- (salsa20/20), 12 (salsa20/12) and 8 (salsa20/8).
salsa20 :: Int -> Matrix -> Matrix
salsa20 rounds m =  foldl' (const . doubleRound) m [1..(rounds `quot` 2) :: Int]
                            `addMatrix` m
{-# INLINE salsa20 #-}

-- | Expands 128Bit key, nonce and counter into initial Matrix representation.
expand128 :: KEY128 -> Nonce -> Counter -> Matrix
expand128 (KEY128 k0 k1 k2 k3)
          (Nonce (SplitWord64 s0 s1))
          (Counter (SplitWord64 s2 s3)) = Matrix (STATE t0 k0 k1 k2)
                                                 (STATE k3 t1 s0 s1)
                                                 (STATE s2 s3 t2 k0)
                                                 (STATE k1 k2 k3 t3)
  where
    t0 = 0x61707865
    t1 = 0x3120646e
    t2 = 0x79622d36
    t3 = 0x6b206574
{-# INLINE expand128 #-}

-- | Expands 256Bit key, nonce and counter into initial Matrix representation.
expand256 :: KEY256 -> Nonce -> Counter -> Matrix
expand256 (KEY256 k0 k1 k2 k3 k4 k5 k6 k7)
          (Nonce (SplitWord64 s0 s1))
          (Counter (SplitWord64 s2 s3)) = Matrix (STATE t0 k0 k1 k2)
                                                 (STATE k3 t1 s0 s1)
                                                 (STATE s2 s3 t2 k4)
                                                 (STATE k5 k6 k7 t3)
  where
    t0 = 0x61707865
    t1 = 0x3320646e
    t2 = 0x79622d32
    t3 = 0x6b206574
{-# INLINE expand256 #-}

-- | Gets the original key, nonce and counter from the matrix representation.
compress128 :: Matrix -> (KEY128,Nonce,Counter)
compress128 (Matrix (STATE _ k0 k1 k2) (STATE k3 _ s0 s1) (STATE s2 s3 _ _) _) =
  (KEY128 k0 k1 k2 k3, Nonce (SplitWord64 s0 s1), Counter (SplitWord64 s2 s3))
{-# INLINE compress128 #-}

-- | Gets the original key, nonce and counter from the matrix representation.
compress256 :: Matrix -> (KEY256,Nonce,Counter)
compress256 (Matrix (STATE _ k0 k1 k2)
                    (STATE k3 _ s0 s1)
                    (STATE s2 s3 _ k4)
                    (STATE k5 k6 k7 _)) = ( KEY256 k0 k1 k2 k3 k4 k5 k6 k7
                                           , Nonce (SplitWord64 s0 s1)
                                           , Counter (SplitWord64 s2 s3)
                                           )
{-# INLINE compress256 #-}


-- | Increments the counter part of the matrix
incrCounter :: Matrix -> Matrix
incrCounter (Matrix s0 s1 (STATE c0 c1 d0 d1) s3) = Matrix s0 s1 (STATE c0' c1' d0 d1) s3
  where
    c0' = c0 + 1
    c1' = if c0' == 0 then c1 + 1 else c1
{-# INLINE incrCounter #-}
