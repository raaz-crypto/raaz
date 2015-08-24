-- | Some generic instances of arbitrary that is needed by other
-- files. This has some orphan instance declarations.

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Generic.Arbitrary where

import Control.Applicative
import Test.QuickCheck(Arbitrary(..))

import Raaz.Core.Types.Word
import Raaz.Core.Classes

instance Arbitrary w => Arbitrary (LE w) where
  arbitrary = LE <$> arbitrary

instance Arbitrary w => Arbitrary (BE w) where
  arbitrary = BE <$> arbitrary

instance Arbitrary w => Arbitrary (BYTES w) where
  arbitrary = BYTES <$> arbitrary


instance Arbitrary w => Arbitrary (BITS w) where
  arbitrary = BITS <$> arbitrary

instance Arbitrary ALIGN where
  arbitrary = toEnum <$> arbitrary
