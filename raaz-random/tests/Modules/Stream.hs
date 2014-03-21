{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Modules.Stream (createGadget,testWith, TestIV(..)) where

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

import           Raaz.Random


-- | Type to capture only integers from 1 to 10
newtype Sized = Sized (BYTES Int) deriving Show

instance Arbitrary Sized where
  arbitrary = Sized . BYTES <$> choose (0,100000)

data TestIV g = TestIV ByteString deriving Show

instance Initializable p => Arbitrary (TestIV p) where
  arbitrary = gen undefined
    where
      gen :: Initializable p => p -> Gen (TestIV p)
      gen p = TestIV . BS.pack <$> vectorOf (fromIntegral $ cxtSize p) arbitrary

createGadget :: (StreamGadget g, Initializable (PrimitiveOf g))
             => g
             -> ByteString
             -> IO (RandomSource g)
createGadget _ bsiv = newInitializedGadget (getCxt bsiv)

prop_length :: (StreamGadget g, Initializable (PrimitiveOf g))
            => g
            -> TestIV (PrimitiveOf g)
            -> Sized    -- ^ Number of bytes to generate
            -> Property
prop_length g' (TestIV bsiv) (Sized sz) = monadicIO $ do
  bs <- run $ generateBytes
  assert (BU.length bs == sz)
  where
    generateBytes = do
      g <- createGadget g' bsiv
      genBytes g sz

testWith :: (StreamGadget g,Initializable (PrimitiveOf g)) => g -> [Test]
testWith g = [ testProperty "genBytes length check" $ prop_length g ]
