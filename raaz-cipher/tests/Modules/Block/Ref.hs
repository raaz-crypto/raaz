{-# LANGUAGE OverloadedStrings #-}
module Modules.Block.Ref
       ( tests
       ) where

import Control.Applicative
import Test.Framework                       (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck                      (Arbitrary(..))


import Raaz.Test                            ()
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

test_encrypt_decrypt128 :: Test
test_encrypt_decrypt128 = testProperty name prop
  where
    prop k s = let expanded = expand128 k
               in decrypt128 (encrypt128 s expanded) expanded == s
    name = "Reference AES128 decrypt . encrypt == id"

test_encrypt_decrypt192 :: Test
test_encrypt_decrypt192 = testProperty name prop
  where
    prop k s = let expanded = expand192 k
               in decrypt192 (encrypt192 s expanded) expanded == s
    name = "Reference AES192 decrypt . encrypt == id"


test_encrypt_decrypt256 :: Test
test_encrypt_decrypt256  = testProperty name prop
  where
    prop k s = let expanded = expand256 k
               in decrypt256 (encrypt256 s expanded) expanded == s
    name = "Reference AES256 decrypt . encrypt == id"

tests :: [Test]
tests = [ test_encrypt_decrypt128
        , test_encrypt_decrypt192
        , test_encrypt_decrypt256
        ]
