{-# LANGUAGE CPP                  #-}
{-# LANGUAGE DataKinds            #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Some common instances that are required by the test cases.
module Common.Instances where

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

genEncodable :: (Encodable a, Storable a) => Gen a
genEncodable = go undefined
  where go :: (Encodable a, Storable a) => a -> Gen a
        go x = unsafeFromByteString . pack <$> vector (sizeOf x)

---------------   Arbitrary instances for Hashes ----------------

instance Arbitrary SHA1 where
  arbitrary = genEncodable

instance Arbitrary SHA224 where
  arbitrary = genEncodable

instance Arbitrary SHA256 where
  arbitrary = genEncodable

instance Arbitrary SHA512 where
  arbitrary = genEncodable

instance Arbitrary SHA384 where
  arbitrary = genEncodable

instance Arbitrary Base16 where
  arbitrary =  (encodeByteString . pack) <$> listOf arbitrary
