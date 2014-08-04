{-# LANGUAGE FlexibleInstances #-}
-- | Tests for the module Types.

module Modules.Types where

import qualified Data.ByteString as BS
import Data.Word
import Test.Framework
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Raaz.Core.Test()
import Raaz.Core.Types
import Raaz.Core.Test.EndianStore

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

tests :: [Test]
tests = [ testStoreLoad (undefined :: (LE Word32))
        , testStoreLoad (undefined :: (BE Word32))
        , testStoreLoad (undefined :: (LE Word64))
        , testStoreLoad (undefined :: (BE Word64))
        , testLEBEreverse32
        , testLEBEreverse64
        ]
