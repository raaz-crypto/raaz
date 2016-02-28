-- | Some generic instances of arbitrary that is needed by other
-- files. This has some orphan instance declarations.

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DataKinds            #-}
module Arbitrary where

import           Control.Applicative
import qualified Data.Vector.Unboxed as V
import           GHC.TypeLits
import           Test.QuickCheck
import           Test.QuickCheck.Monadic
import           Data.ByteString as B
import           Foreign.Storable
import           Raaz.Core

instance Arbitrary w => Arbitrary (LE w) where
  arbitrary = littleEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BE w) where
  arbitrary = bigEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BYTES w) where
  arbitrary = BYTES <$> arbitrary


instance Arbitrary w => Arbitrary (BITS w) where
  arbitrary = BITS <$> arbitrary

instance Arbitrary ALIGN where
  arbitrary = toEnum <$> arbitrary

instance Arbitrary ByteString where
  arbitrary = pack <$> listOf arbitrary

instance (V.Unbox a, Arbitrary a, SingI dim)
         => Arbitrary (Tuple dim a) where
  arbitrary = g
    where gTup   :: (V.Unbox a, SingI dim) => Gen (Tuple dim a)
                                           -> Tuple dim a
          gTup _ = undefined
          g      = fmap unsafeFromList $ vector $ dimension $ gTup g

genStorable :: (Storable a, Encodable a) => Gen a
genStorable = gen
  where proxy    :: Gen a -> a
        proxy _  = undefined
        gen      = unsafeFromByteString . pack <$> vector sz
        sz       = sizeOf $ proxy gen

-- | Generate bytestrings that are multiples of block size of a primitive.
blocks :: Primitive prim => prim -> Gen ByteString
blocks prim = B.concat <$> listOf singleBlock
  where singleBlock = pack <$> vector sz
        BYTES sz    = blockSize prim

feed          :: (Testable prop, Show a) => Gen a -> (a -> IO prop) -> Property
feed gen prop = monadicIO $ pick gen >>= (run . prop)
feedArbitrary :: (Testable prop, Arbitrary a, Show a) => (a -> IO prop) -> Property
feedArbitrary = feed arbitrary
