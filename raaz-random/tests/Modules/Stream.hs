{-# LANGUAGE FlexibleContexts #-}
module Modules.Stream (tests) where

import           Control.Applicative                  ((<$>))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as BS
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (run, assert, monadicIO)

import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Memory
import           Raaz.Types

import Raaz.Random

-- | Type to capture only integers from 1 to 10
newtype Sized = Sized Int deriving Show

instance Arbitrary Sized where
  arbitrary = Sized <$> choose (0,100000)

newtype TestIV = TestIV ByteString deriving Show

instance Arbitrary (TestIV) where
  arbitrary = TestIV . BS.pack
                       <$> vectorOf 1024 arbitrary

prop_length :: (StreamGadget g, Initializable (PrimitiveOf g))
            => g
            -> TestIV
            -> Sized -- ^ Number of bytes to generate
            -> Property
prop_length g' (TestIV bsiv) (Sized sz) = monadicIO $ do
  g <- run $ createGadget g'
  run $ initialize g (getIV bsiv)
  src <- run $ fromGadget g
  bs <- undefined -- generate bytestring from src
  assert (BS.length bs == sz)
  where
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget

tests :: [Test]
tests = []
