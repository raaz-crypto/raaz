{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}
module Modules.Number where

import Control.Applicative
import Data.Bits
import Data.Word
import Test.Framework                       (Test,testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck

import Raaz.Test.EndianStore

import Raaz.Number



instance Arbitrary Word128 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word64
    w2 <- arbitrary :: Gen Word64
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i

instance Arbitrary Word256 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word128
    w2 <- arbitrary :: Gen Word128
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i

instance Arbitrary Word512 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word256
    w2 <- arbitrary :: Gen Word256
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i


instance Arbitrary Word1024 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word512
    w2 <- arbitrary :: Gen Word512
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i


instance Arbitrary Word2048 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word1024
    w2 <- arbitrary :: Gen Word1024
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i


instance Arbitrary Word4096 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word2048
    w2 <- arbitrary :: Gen Word2048
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i


instance Arbitrary Word8192 where
  arbitrary = do
    w1 <- arbitrary :: Gen Word4096
    w2 <- arbitrary :: Gen Word4096
    let w1i = toInteger w1
        w2i = toInteger w2
    return $ fromIntegral $ (1 `shiftL` (bitSize w1 - 1)) * w1i + w2i


prop_bound :: (Num a, Bounded a, Eq a) => a -> Bool
prop_bound a = (maxBound `asTypeOf` a) == minBound - 1

w128 :: Word128
w128 = undefined

w256 :: Word256
w256 = undefined

w512 :: Word512
w512 = undefined

w1024 :: Word1024
w1024 = undefined

w2048 :: Word2048
w2048 = undefined

w4096 :: Word4096
w4096 = undefined

w8192 :: Word8192
w8192 = undefined

testAll w = [ testProperty "Compare" (prop_bound w)
            , testPokePeek w
            ]

tests = [ testGroup "Word128" (testAll w128)
        , testGroup "Word256" (testAll w256)
        , testGroup "Word512" (testAll w512)
        , testGroup "Word1024" (testAll w1024)
        , testGroup "Word2048" (testAll w2048)
        , testGroup "Word4096" (testAll w4096)
        , testGroup "Word8192" (testAll w8192)
        , testGroup "Word4096" (testAll w4096)
        , testGroup "Word4096" (testAll w8192)
        ]
