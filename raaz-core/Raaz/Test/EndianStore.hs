{-|

This module contains some generic tests cases for EndianStore
instances. Whenever a new instance of EndianStore is defined, consider
using them.

-}

module Raaz.Test.EndianStore
       ( testStoreLoad
       , testPokePeek
       ) where

import Data.Typeable
import Foreign.Marshal.Alloc
import Foreign.Storable
import Test.Framework                       ( Test                   )
import Test.Framework.Providers.QuickCheck2 ( testProperty           )
import Test.QuickCheck                      ( Property, Arbitrary    )
import Test.QuickCheck.Monadic              ( run, assert, monadicIO )

import Raaz.Core.Types  ( cryptoAlignment, EndianStore(..) )


-- | This is where the actual store/load is performed.
storeLoad :: (EndianStore a, Eq a) => a -> IO Bool
storeLoad a = allocaBytesAligned (sizeOf a) cryptoAlignment runStoreLoad
  where runStoreLoad ptr = do store ptr a
                              y <- load ptr
                              return $ y == a

-- | This is the property generator. The first value is an unused
-- value and is given to satisfy the typechecker.
prop_StoreLoad :: ( EndianStore a
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
-- > instance EndianStore Foo where
-- >      ...
-- > instance Aribitrary Foo where
-- >      ...
-- > main = defaultMain [ testStoreLoad (undefined :: Foo) ]
--
--
testStoreLoad :: ( EndianStore a
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

-- | This is where the actual poke/peek is performed.
pokePeek :: (Storable a, Eq a) => a -> IO Bool
pokePeek a = allocaBytesAligned (sizeOf a) (alignment a) runPokePeek
  where runPokePeek ptr = do poke ptr a
                             y <- peek ptr
                             return $ y == a

-- | This is the property generator. The first value is an unused
-- value and is given to satisfy the typechecker.
prop_PokePeek :: ( Storable a
                 , Eq a
                 , Show a
                 )
              => a  -- ^ Dummy argument not used
              -> a  -- ^ load and storing is done on this.
              -> Property
prop_PokePeek _ a = monadicIO $ do y <- run $ pokePeek a
                                   assert y

-- | This test checks whether storing followed by loading gives the
-- same value for your instance. The typeable instance is used to
-- print the type when running the test and for nothing else. A
-- typical use would look something like:
--
-- > data Foo = ... deriving (Typeable, Eq, Show)
-- > instance Storable Foo where
-- >      ...
-- > instance Aribitrary Foo where
-- >      ...
-- > main = defaultMain [ testPokePeek (undefined :: Foo) ]
--
--
testPokePeek :: ( Storable a
                , Eq a
                , Show a
                , Arbitrary a
                , Typeable a
                )
             => a    -- ^ dummy argument (not used)
             -> Test
testPokePeek a = testProperty (aType ++ ": Poke/Peek ")
                               $ prop_PokePeek a
     where aType = show $ typeOf a
