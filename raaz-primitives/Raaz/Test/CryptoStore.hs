{-|

This module contains some generic tests cases for CryptoStore
instances. Whenever a new instance of CryptoStore is defined, consider
using them.

-}

module Raaz.Test.CryptoStore
       ( testStoreLoad
       ) where

import Data.Typeable
import Foreign.Marshal.Alloc
import Foreign.Storable
import Test.Framework(Test)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.QuickCheck(Property, Arbitrary)
import Test.QuickCheck.Monadic(run, assert, monadicIO)

import Raaz.Types( cryptoAlignment, CryptoStore(..))


-- | This is where the actual store/load is performed.
storeLoad :: (CryptoStore a, Eq a) => a -> IO Bool
storeLoad a = allocaBytesAligned (sizeOf a) cryptoAlignment runStoreLoad
  where runStoreLoad ptr = do store ptr a
                              y <- load ptr
                              return $ y == a

-- | This is the property generator. The first value is an unused
-- value and is given to satisfy the typechecker.
prop_StoreLoad :: ( CryptoStore a
                  , Eq a
                  , Show a
                  )
               => a  -- ^ Dummy argument not used
               -> a  -- ^ load and storing is done on this.
               -> Property
prop_StoreLoad _ a = monadicIO $ do y <- run $ storeLoad a
                                    assert y

-- | This test checks whether storing followed by loading gives the
-- same value for your instance. The typeable instance is used to
-- print the type when running the test and for nothing else. A
-- typical use would look something like:
--
-- > data Foo = ... deriving (Typeable, Eq, Show)
-- > instance CryptoStore Foo where
-- >      ...
-- > instance Aribitrary Foo where
-- >      ...
-- > main = defaultMain [ testStoreLoad (undefined :: Foo) ]
--
--
testStoreLoad :: ( CryptoStore a
                 , Eq a
                 , Show a
                 , Arbitrary a
                 , Typeable a
                 )
              => a    -- ^ dummy argument (not used)
              -> Test
testStoreLoad a = testProperty (aType ++ ": Store/Load ")
                               $ prop_StoreLoad a
     where aType = show $ typeOf a
