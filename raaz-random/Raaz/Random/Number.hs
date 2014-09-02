{- |

Generate random numbers using `RandomSource`.

-}
{-# LANGUAGE BangPatterns #-}
module Raaz.Random.Number
       ( genMax
       , genBetween
       ) where

import qualified Data.ByteString   as BS
import Data.Word

import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Random.Stream

-- | Generates a positive number i such that 0 <= i <= m. The argument
-- should always be positive.
genMax :: ( StreamGadget g
          , Integral i
          )
       => RandomSource g -- ^ the random source
       -> i              -- ^ the bound
       -> IO i
genMax _ 0 = return 0
genMax rscr maxI | maxI < 0  = error "Illegal arguments"
                 | otherwise = do
  bytes <- genBytes rscr nBytes
  return $ toInt bytes `rem` (maxI + 1)
  where
    toInt = BS.foldl with 0
    with o w = o * 256 + fromIntegral w
    nBytes = go maxI 0
    go 0  !m = m
    go !n !m = go (n `quot` 256) (m+1)

-- | Generates a positive number i such that l <= i <= h
genBetween :: ( StreamGadget g
              , Integral i
              )
           => RandomSource g  -- ^ The random source
           -> i               -- ^ starting value
           -> i               -- ^ ending value
           -> IO i
genBetween rsrc l h = do
  n <- genMax rsrc (h-l)
  return (l+n)
