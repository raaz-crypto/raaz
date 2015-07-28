{-# LANGUAGE FlexibleInstances #-}
-- | Tests for the module Types.

module Core.Types where

import qualified Data.ByteString                      as BS
import           Data.Word
import           Test.QuickCheck                      (Arbitrary)
import           Data.Typeable
import           Test.Framework
import           Test.Framework.Providers.QuickCheck2 (testProperty)

import           Test                       ()
import           Raaz.Core.Types
import           Test.EndianStore

-- | This test captures the property that bytestring encodings of
-- Little Endian word is same as reversing the bytestring encoding of
-- Big endian word.
prop_LEBEreverse32 :: Word32 -> Bool
prop_LEBEreverse32 w = toByteString wle == BS.reverse (toByteString wbe )
       where wle = fromIntegral w :: (LE Word32)
             wbe = fromIntegral w :: (BE Word32)

testLEBEreverse32 :: Test
testLEBEreverse32 = testProperty "LE32 == reverse BE32" prop_LEBEreverse32

prop_LEBEreverse64 :: Word64 -> Bool
prop_LEBEreverse64 w = toByteString wle == BS.reverse (toByteString wbe )
       where wle = fromIntegral w :: (LE Word64)
             wbe = fromIntegral w :: (BE Word64)

testLEBEreverse64 :: Test
testLEBEreverse64 = testProperty "LE64 == reverse BE64" prop_LEBEreverse64

prop_EqWord :: (Arbitrary a, Eq a, EqWord a, Show a) => a -> a -> a -> Bool
prop_EqWord _ a b = (a == b) == (a === b)

testEqWord :: (Arbitrary a, Eq a, EqWord a, Show a, Typeable a) => a -> Test
testEqWord a = testProperty (aType ++ ": == vs ===") $ prop_EqWord a
  where aType = show $ typeOf a

tests :: [Test]
tests = [ testStoreLoad (undefined :: (LE Word32))
        , testStoreLoad (undefined :: (BE Word32))
        , testStoreLoad (undefined :: (LE Word64))
        , testStoreLoad (undefined :: (BE Word64))
        , testEqWord (undefined :: Word8)
        , testEqWord (undefined :: Word16)
        , testEqWord (undefined :: Word32)
        , testEqWord (undefined :: Word64)
        , testEqWord (undefined :: Word)
        , testEqWord (undefined :: LE Word32)
        , testEqWord (undefined :: BE Word32)
        , testEqWord (undefined :: LE Word64)
        , testEqWord (undefined :: BE Word64)
        , testLEBEreverse32
        , testLEBEreverse64
        ]
