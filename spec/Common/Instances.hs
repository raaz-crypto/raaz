{-# LANGUAGE CPP                  #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Some common instances that are required by the test cases.
module Common.Instances where

import Common.Imports
import Common.Utils
import Raaz.Cipher.AES as AES

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

------------------ Arbitrary instances for Keys ---------------

instance Arbitrary AES.KEY128 where
  arbitrary = genEncodable

instance Arbitrary AES.IV where
  arbitrary = genEncodable
