{-# LANGUAGE OverloadedStrings #-}
module Modules.AES.Block () where

import Control.Applicative
import Test.Framework                       ( Test          )
import Test.Framework.Providers.QuickCheck2 ( testProperty  )
import Test.QuickCheck                      ( Arbitrary(..) )

import Test                       ()

import Raaz.Cipher.AES.Internal


instance Arbitrary STATE where
  arbitrary = STATE <$> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitrary

instance Arbitrary KEY128 where
  arbitrary = KEY128 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary


instance Arbitrary KEY192 where
  arbitrary = KEY192 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary

instance Arbitrary KEY256 where
  arbitrary = KEY256 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
