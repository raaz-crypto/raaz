{-|

Generic tests for instances of endian store.

-}

module Generic.EndianStore
       ( storeAndLoadSpec
       ) where

import Test.Hspec
import Test.QuickCheck
import Raaz.Core

import Arbitrary

storeAndLoadSpec :: (EndianStore a, Arbitrary a, Eq a, Show a)
                 => a  -- ^ Value unused. Only to make type checker happy.
                 -> Spec
storeAndLoadSpec a = do
  it "checks whether store followed by load gives the same value" $ do
    feedArbitrary $ storeLoad a
  where storeLoad :: (EndianStore a, Eq a) => a -> a -> IO Bool
        storeLoad _ x = allocaBuffer (byteSize x) $ runStoreLoad
          where runStoreLoad ptr = fmap (==x) $ store ptr x >> load ptr
