{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE NoMonomorphismRestriction  #-}
module Modules.Stream (createGadget,testWith, testiv) where

import           Control.Applicative                  ((<$>))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as BS
import           Foreign.Storable                     (sizeOf)
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (run, assert, monadicIO)

import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import qualified Raaz.Util.ByteString                 as BU
import           Raaz.Memory
import           Raaz.Serialize
import           Raaz.Types

import           Raaz.Random

-- | Type to capture only integers from 1 to 10
newtype Sized = Sized (BYTES Int) deriving Show

instance Arbitrary Sized where
  arbitrary = Sized . BYTES <$> choose (0,100000)

testiv = fromByteString $ BS.replicate 10000 1 -- Assuming no key is less than this

createGadget :: ( StreamGadget g
                , PrimitiveOf g ~ prim EncryptMode
                , Encrypt prim
                )
             => g
             -> Key (prim EncryptMode)
             -> IO (RandomSource g)
createGadget _ = newInitializedGadget . RSCxt . encryptCxt

prop_length :: ( StreamGadget g
               , PrimitiveOf g ~ prim EncryptMode
               , Encrypt prim
               )
            => g
            -> Key (prim EncryptMode)
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
            , PrimitiveOf g ~ prim EncryptMode
            , Encrypt prim
            ) => g -> [Test]
testWith g = [ testProperty "genBytes length check" $ prop_length g testiv ]
