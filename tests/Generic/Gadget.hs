{- |

This module is for testing a gadget against the reference
implementation.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs            #-}

module Generic.Gadget
       ( testGadget
       , testGadgetFinal
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

genByteString :: LengthUnit l => l -> Gen ByteString
genByteString l = B.pack <$> vectorOf n arbitrary
  where BYTES n = inBytes l

chooseLengthUnits :: LengthUnit l => (Int, Int) -> Gen l
chooseLengthUnits range = fromIntegral <$> choose range

instance Primitive p => Arbitrary (TestData p) where
  arbitrary = chooseLengthUnits (1,100) >>= gen
    where gen :: Primitive p =>  BLOCKS p -> Gen (TestData p)
          gen nblocks = TestData <$> genByteString nblocks



-- | Checks if the result of applying the two gadgets on a buffer
-- gives the same results. Only the contents of the buffer are
-- compared.
checkBuffer :: (Gadget g, Gadget ref, prim ~ PrimitiveOf g, prim  ~ PrimitiveOf ref)
            => TestData prim
            -> ref
            -> g
            -> IO Bool
checkBuffer (TestData bs) ref g = (==) <$> applyOnByteString g bs <*> applyOnByteString ref bs

-- | Check whether the final values produced are the same
checkFV :: ( Gadget g
           , Gadget ref
           , FinalizableMemory g
           , FinalizableMemory ref
           , FV ref ~ FV g
           , Eq (FV g)
           , prim ~ PrimitiveOf g, prim ~ PrimitiveOf ref
           )
           => TestData prim
           -> ref
           -> g
           -> IO Bool
checkFV (TestData bs) ref g = (==) <$> getFV ref <*> getFV g
  where getFV :: ( Gadget g
                 , FinalizableMemory g
                 )
                 => g -> IO (FV g)
        getFV gadget = allocaBuffer (BU.length bs) go
          where go cptr = applyGadget gadget bs cptr >> finalizeMemory gadget


-- | Check whether running the gadget and its inverse results in the
-- same buffer contents.
checkInverse :: ( Gadget g
                , Gadget g'
                )
             => TestData (PrimitiveOf g)
             -> g  -- ^ Gadget
             -> g' -- ^ Inverse Gadget
             -> IO Bool
checkInverse (TestData bs) g1 g2 = do
  outbs <- applyOnByteString g1 bs
  bs'   <- applyOnByteString g2 outbs
  return $ bs == bs'

-- | Tests the given gadget against a reference one.
testGadget :: ( Gadget g
              , HasName g
              , Gadget ref
              , HasName ref
              , prim ~ PrimitiveOf g, prim ~ PrimitiveOf ref
              , Eq (IV g)
              )
           => ref
           -> g
           -> Key prim
           -> Test
testGadget ref g key = testProperty msg prop
  where msg = getName g ++ " VS " ++ getName ref
        prop tdata = monadicIO $ run (with2Gadgets ref g key key $ checkBuffer tdata) >>= assert

testGadgetFinal :: ( Gadget g
                   , Gadget ref
                   , HasName g
                   , HasName ref
                   , FinalizableMemory g
                   , FinalizableMemory ref
                   , FV ref ~ FV g
                   , Eq (FV g)
                   , PrimitiveOf g ~ PrimitiveOf ref
                   )
                => g
                -> ref
                -> IV g
                -> Test
testGadgetFinal g ref key = testProperty msg prop
  where msg = getName g ++ " VS " ++ getName ref
        prop tdata = monadicIO $ run (with2Gadgets ref g key key $ checkFV tdata) >>= assert


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
testInverse g1 g2 key1 key2 = testProperty msg prop
  where msg = getName g1 ++ " . " ++ getName g2 ++ " == id"
        prop tdata = monadicIO $ run (with2Gadgets g1 g2 key1 key2 $ checkInverse tdata) >>= assert


----------------------- Some helper functions -----------------------------------

-- | Apply the gadget on a bytestring and return the resulting bytestring.
applyOnByteString      :: Gadget g => g -> ByteString -> IO ByteString
applyOnByteString g bs = create bsize $ applyGadget g bs . castPtr
  where BYTES bsize = BU.length bs

-- | Applies a given gadget on a byte string.
applyGadget :: Gadget g => g -> ByteString -> CryptoPtr -> IO ()
applyGadget g bs cptr = BU.unsafeCopyToCryptoPtr bs cptr
                        >> apply g (atMost (BU.length bs)) cptr


withNewGadget :: Gadget g => g -> Key (PrimitiveOf g) -> (g -> IO a) -> IO a
withNewGadget _ key action = withGadget key action

with2Gadgets :: (Gadget g1, Gadget g2 )
             => g1 -> g2
             -> Key (PrimitiveOf g1) -> Key (PrimitiveOf g2)
             -> (g1 -> g2 -> IO a)
             -> IO a
with2Gadgets g1 g2 k1 k2 action = withNewGadget g1 k1 $ actionG1
  where actionG1 newG1  = withNewGadget g2 k2 $ action newG1
