-- | Tests for the module Types.


module Modules.Types where

import Data.Word
import Test.QuickCheck

import Raaz.Types
import Raaz.Test.CryptoStore


instance Arbitrary Word32LE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word32)

instance Arbitrary Word32BE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word32)

instance Arbitrary Word64LE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word64)

instance Arbitrary Word64BE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word64)

tests = [ testStoreLoad (undefined :: Word32LE)
        , testStoreLoad (undefined :: Word32BE)
        , testStoreLoad (undefined :: Word64LE)
        , testStoreLoad (undefined :: Word64BE)
        ]
