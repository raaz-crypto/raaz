{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Instance declarations for all types in Raaz.Types
module Raaz.Test.Instances() where

import Data.Word
import Test.QuickCheck(Arbitrary(..), Gen)
import Raaz.Types( Word32LE, Word32BE
                 , Word64LE, Word64BE
                 , BYTES(..), BITS(..)
                 )

instance Arbitrary Word32LE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word32)

instance Arbitrary Word32BE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word32)

instance Arbitrary Word64LE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word64)

instance Arbitrary Word64BE where
  arbitrary = fmap fromIntegral (arbitrary :: Gen Word64)


instance Arbitrary bits => Arbitrary (BITS bits) where
  arbitrary = fmap BITS arbitrary

instance Arbitrary bytes => Arbitrary (BYTES bytes) where
  arbitrary = fmap BYTES arbitrary
