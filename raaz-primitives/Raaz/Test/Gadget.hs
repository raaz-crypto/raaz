{-

This module is for testing a gadget against the reference
implementation.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs            #-}

module Raaz.Test.Gadget (testGadget) where

import           Control.Applicative
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B
import           Data.ByteString.Internal             (create)
import           Foreign.Ptr
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (run, assert, monadicIO)

import           Raaz.Memory
import           Raaz.Primitives
import qualified Raaz.Util.ByteString                 as BU
import           Raaz.Util.Ptr
import           Raaz.Types

-- | Type to capture only integers from 1 to 10
data Sized = Sized Int deriving Show

-- | Type to capture ByteString of size Sized
data TestData p = TestData ByteString deriving Show

instance Arbitrary Sized where
  arbitrary = Sized <$> choose (1,10)

instance Primitive p => Arbitrary (TestData p) where
  arbitrary = do
    (Sized s) <- arbitrary
    generate undefined s
    where
      generate :: Primitive p => p -> Int -> Gen (TestData p)
      generate p s = TestData . B.pack
                     <$> vectorOf (s * (fromIntegral $ blockSize p)) arbitrary

prop_Gadget :: (Gadget g, Gadget ref, PrimitiveOf g ~ PrimitiveOf ref, Eq (PrimitiveOf g))
            => ref
            -> g
            -> IV (PrimitiveOf g)
            -> TestData (PrimitiveOf g)
            -> Property
prop_Gadget ref' g' iv (TestData bs) = monadicIO $ do
  g   <- run $ createGadget g'
  run $ initialize g iv
  ref <- run $ createGadget ref'
  run $ initialize ref iv
  outg <- run $ allocaBuffer bsize (with g)
  outref <- run $ allocaBuffer bsize (with ref)
  assert (outg == outref)
  where
    bsize = BU.length bs
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget =<< newMemory
    with :: Gadget g => g -> CryptoPtr -> IO (PrimitiveOf g, ByteString)
    with g cptr =  do
      BU.unsafeCopyToCryptoPtr bs cptr
      apply g (fromIntegral numBlocks) cptr
      out <- finalize g
      outbs <- create (fromIntegral bsize) copyTo
      return (out,outbs)
      where
        copyTo ptr = memcpy (castPtr ptr) cptr bsize
        numBlocks = bsize `div` oneBlock
        oneBlock = fromIntegral $ blockSize (getPrim g')
        getPrim :: Gadget g => g -> PrimitiveOf g
        getPrim _ = undefined

testGadget :: ( Gadget g
              , Gadget ref
              , PrimitiveOf g ~ PrimitiveOf ref
              , Eq (PrimitiveOf g)
              )
           => g
           -> ref
           -> IV (PrimitiveOf g)
           -> String
           -> Test
testGadget g ref iv msg = testProperty msg
                                   $ prop_Gadget g ref iv
