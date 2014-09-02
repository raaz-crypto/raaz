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
genMax :: (StreamGadget g, Integral i) => RandomSource g -> i -> IO i
genMax _ 0 = return 0
genMax rscr maxI | maxI < 0  = error "Illegal arguments"
                 | otherwise = do
  bytes <- genBytes rscr nBytes
  return $ toInt bytes `mod` (maxI + 1)
  where
    toInt = BS.foldl with 0
    with o w = o * 256 + fromIntegral w
    nBytes = go maxI 0
      where
        go 0 !m = m
        go !n !m = go (n `div` 256) (m+1)
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Int      -> IO Int      #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Integer  -> IO Integer  #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Word8    -> IO Word8    #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> BE Word32 -> IO (BE Word32) #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> LE Word32 -> IO (LE Word32) #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> BE Word64 -> IO (BE Word64) #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> LE Word64 -> IO (LE Word64) #-}


-- | Generates a positive number i such that l <= i <= h
genBetween :: (StreamGadget g,Integral i) => RandomSource g -> i -> i -> IO i
genBetween rsrc l h = do
  n <- genMax rsrc (h-l)
  return (l+n)
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Int      -> Int      -> IO Int      #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Integer  -> Integer  -> IO Integer  #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word8    -> Word8    -> IO Word8    #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> BE Word32 -> BE Word32 -> IO (BE Word32) #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> LE Word32 -> LE Word32 -> IO (LE Word32) #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> BE Word64 -> BE Word64 -> IO (BE Word64) #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> LE Word64 -> LE Word64 -> IO (LE Word64) #-}
