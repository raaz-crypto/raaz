-- | Tests for the module Types.


module Modules.Types where

import qualified Data.ByteString as BS
import Data.Word
import Test.QuickCheck
import Test.Framework
import Test.Framework.Providers.QuickCheck2 (testProperty)

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

-- | This test captures the property that bytestring encodings of Little
-- Endian word is same as reversing the bytestring encoding of Big endian word.
prop_LEBEreverse32 :: Word32 -> Bool
prop_LEBEreverse32 w = toByteString wle == BS.reverse (toByteString wbe )
       where wle = fromIntegral w :: Word32LE
             wbe = fromIntegral w :: Word32BE

testLEBEreverse32 :: Test
testLEBEreverse32 = testProperty "ReverseLEBE32" prop_LEBEreverse32

prop_LEBEreverse64 :: Word64 -> Bool
prop_LEBEreverse64 w = toByteString wle == BS.reverse (toByteString wbe )
       where wle = fromIntegral w :: Word64LE
             wbe = fromIntegral w :: Word64BE

testLEBEreverse64 :: Test
testLEBEreverse64 = testProperty "ReverseLEBE64" prop_LEBEreverse64

tests = [ testStoreLoad (undefined :: Word32LE)
        , testStoreLoad (undefined :: Word32BE)
        , testStoreLoad (undefined :: Word64LE)
        , testStoreLoad (undefined :: Word64BE)
        , testLEBEreverse32
        , testLEBEreverse64
        ]
