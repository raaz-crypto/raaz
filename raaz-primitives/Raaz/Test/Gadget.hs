{- |

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

-- | Quickcheck property of testing a gadget against a reference one.
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

-- | Apply a gadget on the given bytestring.
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

-- | Quickcheck test for gadget . inverseGadget is identity
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

-- | Tests the given gadget against a reference one.
testGadget :: ( Gadget g
              , HasName g
              , Gadget ref
              , HasName ref
              , PrimitiveOf g ~ PrimitiveOf ref
              , Eq (Cxt (PrimitiveOf g))
              )
           => g
           -> ref
           -> Cxt (PrimitiveOf g)
           -> Test
testGadget g ref cxt = testProperty msg $ prop_Gadget g ref cxt
  where msg = getName g ++ " VS " ++ getName ref

-- | Tests g . inverseGadget g == id
testInverse :: ( Gadget g
               , HasInverse g
               , HasName g
               , HasName (Inverse g)
               )
            => g
            -> Cxt (PrimitiveOf g)
            -> Cxt (PrimitiveOf (Inverse g))
            -> Test
testInverse g cxt icxt = testProperty msg $ prop_inverse g cxt icxt
  where msg = getName g ++ " . " ++ getName (inverseGadget g) ++ " == id"
