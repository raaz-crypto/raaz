{- |

This module is for testing a gadget against the reference
implementation.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs            #-}

module Test.Gadget
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

import           Raaz.Core.Primitives
import           Raaz.Core.Memory
import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString                 as BU
import           Raaz.Core.Util.Ptr

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
                     <$> vectorOf (s * fromIntegral (blockSize p)) arbitrary

-- | Quickcheck property of testing a gadget against a reference
-- one. It only checks the underlying buffer and not the final value
-- produced.
prop_Gadget :: (Gadget g, Gadget ref, PrimitiveOf g ~ PrimitiveOf ref)
            => ref
            -> g
            -> IV (MemoryOf g)
            -> TestData (PrimitiveOf g)
            -> Property
prop_Gadget ref' g' cxt (TestData bs) = monadicIO $ do
  g   <- run $ createGadget g' cxt
  ref <- run $ createGadget ref' cxt
  outg <- run $ onByteString g bs
  outref <- run $ onByteString ref bs
  assert (outg == outref)

-- | Apply a gadget on the given bytestring.
onByteString :: Gadget g => g -> ByteString -> IO ByteString
onByteString g bs = create (fromIntegral bsize) (applyTo . castPtr)
  where
    bsize = BU.length bs
    applyTo ptr =  BU.unsafeCopyToCryptoPtr bs ptr
                >> apply g numBlocks ptr
    numBlocks = atMost bsize


-- | Quickcheck property to test final value produced by gadgets.
prop_GadgetFinal :: ( Gadget g
                    , Gadget ref
                    , FinalizableMemory (MemoryOf g)
                    , FinalizableMemory (MemoryOf ref)
                    , FV (MemoryOf ref) ~ FV (MemoryOf g)
                    , Eq (FV (MemoryOf g))
                    , PrimitiveOf g ~ PrimitiveOf ref
                    )
                 => ref
                 -> g
                 -> IV (MemoryOf g)
                 -> TestData (PrimitiveOf g)
                 -> Property
prop_GadgetFinal ref' g' cxt (TestData bs) = monadicIO $ do
  g   <- run $ createGadget g' cxt
  ref <- run $ createGadget ref' cxt
  run $ initialize ref cxt
  fvg <- run $ getFV g
  fvref <- run $ getFV ref
  assert (fvg == fvref)
  where
    bsize = BU.length bs
    getFV :: ( Gadget g
             , FinalizableMemory (MemoryOf g)
             )
          => g -> IO (FV (MemoryOf g))
    getFV g = allocaBuffer bsize (with g . castPtr)
      where
        with g ptr =  BU.unsafeCopyToCryptoPtr bs ptr
                   >> apply g (atMost bsize) ptr
                   >> finalize g

-- | Quickcheck test for inverseGadget . gadget is identity. It is
-- mainly useful in checking the working of encrypt and decrypt
-- gadgets.
prop_inverse :: ( Gadget g
                , Gadget g'
                )
             => g  -- ^ Gadget
             -> g' -- ^ Inverse Gadget
             -> Key (PrimitiveOf g)
             -> Key (PrimitiveOf g')
             -> TestData (PrimitiveOf g)
             -> Property
prop_inverse g1' g2' cxtg cxtig (TestData bs) = monadicIO $ do
  g1 <- run $ createGadget g1'
  run $ initialize g1 cxtg
  g2 <- run $ createGadget g2'
  run $ initialize g2 cxtig
  outbs <- run $ onByteString g1 bs
  bs' <- run $ onByteString g2 outbs
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
              , Eq (IV (MemoryOf g))
              )
           => g
           -> ref
           -> IV (MemoryOf g)
           -> Test
testGadget g ref cxt = testProperty msg $ prop_Gadget g ref cxt
  where msg = getName g ++ " VS " ++ getName ref

testGadgetFinal :: ( Gadget g
                   , Gadget ref
                   , HasName g
                   , HasName ref
                   , FinalizableMemory (MemoryOf g)
                   , FinalizableMemory (MemoryOf ref)
                   , FV (MemoryOf ref) ~ FV (MemoryOf g)
                   , Eq (FV (MemoryOf g))
                   , PrimitiveOf g ~ PrimitiveOf ref
                   )
                => g
                -> ref
                -> IV (MemoryOf g)
                -> Test
testGadgetFinal g ref cxt = testProperty msg $ prop_GadgetFinal g ref cxt
  where msg = getName g ++ " VS " ++ getName ref


-- | Tests g . inverseGadget g == id
testInverse :: ( Gadget g
               , Gadget g'
               , HasName g
               , HasName g'
               )
            => g
            -> g'
            -> Key (PrimitiveOf g)
            -> Key (PrimitiveOf g')
            -> Test
testInverse g g' cxt icxt = testProperty msg $ prop_inverse g g' cxt icxt
  where msg = getName g' ++ " . " ++ getName g ++ " == id"

createGadget :: Gadget g => g -> IV (MemoryOf g)-> IO g
createGadget _ = newInitializedGadget
