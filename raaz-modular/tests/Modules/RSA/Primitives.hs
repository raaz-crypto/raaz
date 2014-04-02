{-# OPTIONS_GHC -fno-warn-orphans #-}
module Modules.RSA.Primitives (tests) where

import           Control.Applicative                  ((<$>))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as BS
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck

import           Raaz.Types

import           Raaz.RSA.Primitives

data TestBS = TestBS ByteString deriving (Show,Eq)

instance Arbitrary TestBS where
  arbitrary = TestBS . BS.pack <$> arbitrary

data Compatible = Comp Integer Int deriving Show

instance Arbitrary Compatible where
  arbitrary  = do
    a <- choose (1,50)
    b <- choose (0, 256 ^ a)
    return (Comp b a)

prop_i2osp_os2ip :: Compatible -> Bool
prop_i2osp_os2ip (Comp x xLen) = os2ip (i2osp x (BYTES xLen)) == x

testI2ospOs2ip :: Test
testI2ospOs2ip = testProperty "Primitivive: i2osp/os2ip" prop_i2osp_os2ip

prop_os2ip_i2osp :: TestBS -> Bool
prop_os2ip_i2osp (TestBS b) = i2osp (os2ip b) (BYTES $ BS.length b) == b

testOs2ipI2osp :: Test
testOs2ipI2osp = testProperty "Primitivive: os2ip/i2osp" prop_os2ip_i2osp

tests :: [Test]
tests = [ testI2ospOs2ip
        , testOs2ipI2osp
        ]
