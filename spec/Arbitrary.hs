-- | Some generic instances of arbitrary that is needed by other
-- files. This has some orphan instance declarations.

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Arbitrary where

import Control.Applicative
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Raaz.Core.Types.Word
import Raaz.Core.Classes

instance Arbitrary w => Arbitrary (LE w) where
  arbitrary = littleEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BE w) where
  arbitrary = bigEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BYTES w) where
  arbitrary = BYTES <$> arbitrary


instance Arbitrary w => Arbitrary (BITS w) where
  arbitrary = BITS <$> arbitrary

instance Arbitrary ALIGN where
  arbitrary = toEnum <$> arbitrary

feed          :: (Testable prop, Show a) => Gen a -> (a -> IO prop) -> Property
feed gen prop = monadicIO $ pick gen >>= (run . prop)
feedArbitrary :: (Testable prop, Arbitrary a, Show a) => (a -> IO prop) -> Property
feedArbitrary = feed arbitrary
