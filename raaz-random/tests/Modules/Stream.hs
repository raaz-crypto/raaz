{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE NoMonomorphismRestriction  #-}
module Modules.Stream ( createGadget
                      , testWith
                      ) where

import           Control.Applicative                  ( (<$>)                  )
import           Data.ByteString                      ( ByteString             )
import qualified Data.ByteString                      as BS
import           Foreign.Storable                     ( sizeOf                 )
import           Test.Framework                       ( Test                   )
import           Test.Framework.Providers.QuickCheck2 ( testProperty           )
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              ( run, assert, monadicIO )

import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString            as BU

import           Raaz.Random

-- | Type to capture only integers from 1 to 10
newtype Sized = Sized (BYTES Int) deriving Show

instance Arbitrary Sized where
  arbitrary = Sized . BYTES <$> choose (0,100000)

createGadget :: ( StreamGadget g
                , prim ~ PrimitiveOf g
                , Cipher prim
                )
             => g
             -> Key prim
             -> IO (RandomSource g)
createGadget g = newInitializedGadget . cipherCxt (primitiveOf g)

prop_length :: ( StreamGadget g
               , prim ~ PrimitiveOf g
               , Cipher prim
               )
            => g
            -> Key prim
            -> Sized                     -- ^ Number of bytes to generate
            -> Property
prop_length g' k (Sized sz) = monadicIO $ do
  bs <- run $ generateBytes
  assert (BU.length bs == sz)
  where
    generateBytes = do
      g <- createGadget g' k
      genBytes g sz

testWith :: ( StreamGadget g
            , Cipher prim
            , prim ~ PrimitiveOf g
            ) => g -> Key prim -> [Test]
testWith g k = [ testProperty "genBytes length check" $ prop_length g k ]
