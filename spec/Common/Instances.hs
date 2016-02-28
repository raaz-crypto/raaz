{-# LANGUAGE DataKinds            #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Some common instances that are required by the test cases.
module Common.Instances where

import Data.Vector.Unboxed         as  V
import GHC.TypeLits
import Raaz.Hash.Sha1.Internal
import Raaz.Hash.Sha224.Internal
import Raaz.Hash.Sha256.Internal
import Raaz.Hash.Sha512.Internal
import Raaz.Hash.Sha384.Internal

import Common.Imports

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
  arbitrary = pack <$> arbitrary

instance (V.Unbox a, Arbitrary a, SingI dim)
         => Arbitrary (Tuple dim a) where
  arbitrary = g
    where gTup   :: (V.Unbox a, SingI dim) => Gen (Tuple dim a)
                                           -> Tuple dim a
          gTup _ = undefined
          g      = fmap unsafeFromList $ vector $ dimension $ gTup g

---------------   Arbitrary instances for Hashes ----------------

instance Arbitrary SHA1 where
  arbitrary = SHA1   <$> arbitrary

instance Arbitrary SHA224 where
  arbitrary = SHA224 <$> arbitrary

instance Arbitrary SHA256 where
  arbitrary = SHA256 <$> arbitrary

instance Arbitrary SHA512 where
  arbitrary = SHA512 <$> arbitrary

instance Arbitrary SHA384 where
  arbitrary = SHA384 <$> arbitrary


instance Arbitrary Base16 where
  arbitrary =  (encodeByteString . pack) <$> listOf arbitrary
