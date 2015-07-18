{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}
module Modules.Number (testWith) where

import           Control.Applicative                  ((<$>))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as BS
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (assert, monadicIO, run)

import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString            as BU

import           Modules.Stream                       (createGadget)
import           Raaz.Random

import           Data.Word
-- | MinMax mi ma where ma >= mi >= 0
data MinMax = MinMax Int Int deriving Show

instance Arbitrary MinMax where
  arbitrary = do
    ma <- choose (0,100000)
    mi <- choose (0,ma)
    return $ MinMax mi ma

prop_max :: ( StreamGadget g
            , PrimitiveOf g ~ prim
            , Cipher prim
            )
         => g
         -> Key prim
         -> Positive Int
         -> Property
prop_max g' k (Positive maxi) = monadicIO $ do
  i <- run generateInt
  assert (i >= 0)
  assert (i <= maxi)
  where
    generateInt = do
      g <- createGadget g' k
      genMax g maxi

prop_between :: ( StreamGadget g
                , PrimitiveOf g ~ prim
                , Cipher prim
                )
             => g
             -> Key prim
             -> MinMax
             -> Property
prop_between g' k (MinMax mini maxi) = maxi > mini ==> monadicIO $ do
  i <- run generateInt
  assert (i >= mini)
  assert (i <= maxi)
  where
    generateInt = do
      g <- createGadget g' k
      genBetween g mini maxi

testWith :: ( StreamGadget g
            , PrimitiveOf g ~ prim
            , Cipher prim
            )
         => g -> Key prim -> [Test]
testWith g k = [ testProperty "genMax domain check" $ prop_max g k
               , testProperty "genBetween domain check" $ prop_between g k
               ]
