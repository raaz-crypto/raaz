{-

This module is for testing a gadget against the reference
implementation.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs            #-}

module Raaz.Test.Gadget
       ( testGadget
       , testInverse
       ) where

import           Control.Applicative
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B
import           Data.ByteString.Internal             (create)
import           Foreign.Ptr
import           Test.Framework                       (Test)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
import           Test.QuickCheck.Monadic              (run, assert, monadicIO)

import           Raaz.Primitives
import qualified Raaz.Util.ByteString                 as BU
import           Raaz.Util.Ptr

-- | Type to capture only integers from 1 to 10
data Sized = Sized Int deriving Show

-- | Type to capture ByteString of size Sized
data TestData p = TestData ByteString deriving Show

instance Arbitrary Sized where
  arbitrary = Sized <$> choose (1,100)

instance Primitive p => Arbitrary (TestData p) where
  arbitrary = do
    (Sized s) <- arbitrary
    generate undefined s
    where
      generate :: Primitive p => p -> Int -> Gen (TestData p)
      generate p s = TestData . B.pack
                     <$> vectorOf (s * (fromIntegral $ blockSize p)) arbitrary

prop_Gadget :: (Gadget g, Gadget ref, PrimitiveOf g ~ PrimitiveOf ref, Eq (Cxt (PrimitiveOf g)))
            => ref
            -> g
            -> Cxt (PrimitiveOf g)
            -> TestData (PrimitiveOf g)
            -> Property
prop_Gadget ref' g' cxt (TestData bs) = monadicIO $ do
  g   <- run $ createGadget g'
  run $ initialize g cxt
  ref <- run $ createGadget ref'
  run $ initialize ref cxt
  outg <- run $ onByteString g bs
  outref <- run $ onByteString ref bs
  assert (outg == outref)
  where
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget

onByteString :: Gadget g => g -> ByteString -> IO (Cxt (PrimitiveOf g), ByteString)
onByteString g bs =  allocaBuffer bsize with
  where
    bsize = BU.length bs
    with cptr = do
      BU.unsafeCopyToCryptoPtr bs cptr
      apply g (fromIntegral numBlocks) cptr
      out <- finalize g
      outbs <- create (fromIntegral bsize) copyTo
      return (out,outbs)
      where
        copyTo ptr = memcpy (castPtr ptr) cptr bsize
        numBlocks = bsize `div` oneBlock
        oneBlock = fromIntegral $ blockSize (primitiveOf g)

prop_inverse :: ( Gadget g
                , HasInverse g
                )
             => g
             -> Cxt (PrimitiveOf g)
             -> Cxt (PrimitiveOf (Inverse g))
             -> TestData (PrimitiveOf g)
             -> Property
prop_inverse g' cxtg cxtig (TestData bs) = monadicIO $ do
  g   <- run $ createGadget g'
  run $ initialize g cxtg
  gInv <- run $ createGadget (inverseGadget g')
  run $ initialize gInv cxtig
  (_,outbs) <- run $ onByteString g bs
  (_,bs') <- run $ onByteString gInv outbs
  assert (bs == bs')
  where
    createGadget :: Gadget g => g -> IO g
    createGadget _ = newGadget

testGadget :: ( Gadget g
              , Gadget ref
              , PrimitiveOf g ~ PrimitiveOf ref
              , Eq (Cxt (PrimitiveOf g))
              )
           => g
           -> ref
           -> Cxt (PrimitiveOf g)
           -> String
           -> Test
testGadget g ref cxt msg = testProperty msg
                                   $ prop_Gadget g ref cxt

testInverse :: ( Gadget g
               , HasInverse g
               )
            => g
            -> Cxt (PrimitiveOf g)
            -> Cxt (PrimitiveOf (Inverse g))
            -> String
            -> Test
testInverse g cxt icxt msg = testProperty msg
                              $ prop_inverse g cxt icxt
