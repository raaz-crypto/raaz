{-# LANGUAGE FlexibleContexts #-}
module Modules.Number (testWith) where

import           Control.Applicative                  ((<$>))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as BS
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (run, assert, monadicIO)

import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import qualified Raaz.Util.ByteString                 as BU
import           Raaz.Memory
import           Raaz.Types

import           Modules.Stream                       (createGadget,TestIV(..))
import           Raaz.Random

import Data.Word
-- | MinMax mi ma where ma >= mi >= 0
data MinMax = MinMax Int Int deriving Show

instance Arbitrary MinMax where
  arbitrary = do
    ma <- choose (0,100000)
    mi <- choose (0,ma)
    return $ MinMax mi ma

prop_max :: (StreamGadget g, Initializable (PrimitiveOf g))
         => g
         -> TestIV (PrimitiveOf g)
         -> Positive Int
         -> Property
prop_max g' (TestIV bsiv) maxi = monadicIO $ do
  i <- run $ generateInt
  assert (i >= 0)
  assert (i <= maxi)
  where
    generateInt = do
      g <- createGadget g' bsiv
      genMax g maxi

prop_between :: (StreamGadget g, Initializable (PrimitiveOf g))
             => g
             -> TestIV (PrimitiveOf g)
             -> MinMax
             -> Property
prop_between g' (TestIV bsiv) (MinMax mini maxi) = maxi > mini ==> monadicIO $ do
  i <- run $ generateInt
  assert (i >= mini)
  assert (i <= maxi)
  where
    generateInt = do
      g <- createGadget g' bsiv
      genBetween g mini maxi

testWith :: (StreamGadget g,Initializable (PrimitiveOf g)) => g -> [Test]
testWith g = [ testProperty "genMax domain check" $ prop_max g
             , testProperty "genBetween domain check" $ prop_between g
             ]
