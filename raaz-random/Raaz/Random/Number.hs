{- |

Generate random numbers using `RandomSource`.

-}
{-# LANGUAGE BangPatterns #-}
module Raaz.Random.Number
       ( genMax
       , genBetween
       ) where

import qualified Data.ByteString        as BS
import Data.Word

import Raaz.Primitives.Cipher
import Raaz.Random.Stream
import Raaz.Types

-- | Generates a positive number i such that 0 <= i <= m
genMax :: (StreamGadget g, Integral i) => RandomSource g -> i -> IO i
genMax _ 0 = return 0
genMax rscr maxI = do
  bytes <- genBytes rscr nBytes
  return $ toInt bytes `mod` maxI
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
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Word32BE -> IO Word32BE #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Word32LE -> IO Word32LE #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Word64BE -> IO Word64BE #-}
{-# SPECIALIZE genMax :: StreamGadget g => RandomSource g -> Word64LE -> IO Word64LE #-}


-- | Generates a positive number i such that l <= i <= h
genBetween :: (StreamGadget g,Integral i) => RandomSource g -> i -> i -> IO i
genBetween rsrc l h = do
  n <- genMax rsrc (h-l-1)
  return (l+n)
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Int      -> Int      -> IO Int      #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Integer  -> Integer  -> IO Integer  #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word8    -> Word8    -> IO Word8    #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word32BE -> Word32BE -> IO Word32BE #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word32LE -> Word32LE -> IO Word32LE #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word64BE -> Word64BE -> IO Word64BE #-}
{-# SPECIALIZE genBetween :: StreamGadget g => RandomSource g -> Word64LE -> Word64LE -> IO Word64LE #-}
