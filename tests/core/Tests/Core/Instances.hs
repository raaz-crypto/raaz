{-# LANGUAGE CPP                  #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Some common instances that are required by the test cases.
module Tests.Core.Instances where

import Tests.Core.Imports
import Tests.Core.Utils

import Raaz.Primitive.ChaCha20.Internal (ChaCha20, XChaCha20)
import Raaz.Primitive.Poly1305.Internal as Poly1305
import Raaz.Core.Types.Internal

instance Arbitrary w => Arbitrary (LE w) where
  arbitrary = littleEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BE w) where
  arbitrary = bigEndian <$> arbitrary

instance Arbitrary w => Arbitrary (BYTES w) where
  arbitrary = BYTES <$> arbitrary


instance Arbitrary w => Arbitrary (BITS w) where
  arbitrary = BITS <$> arbitrary

instance Arbitrary ByteString where
  arbitrary = pack <$> arbitrary


---------------   Arbitrary instances for Hashes ----------------

instance Arbitrary Sha256 where
  arbitrary = genEncodable

instance Arbitrary Sha512 where
  arbitrary = genEncodable

instance Arbitrary Blake2b where
  arbitrary = genEncodable

instance Arbitrary Blake2s where
  arbitrary = genEncodable

---------------- Parameter block for Blake          -------------

---------------- Arbitrary instaces of encoded data --------------

instance Arbitrary Base16 where
  arbitrary =  encodeByteString . pack <$> listOf arbitrary

instance Arbitrary Base64 where
  arbitrary =  encodeByteString . pack <$> listOf arbitrary

------------------ For ChaCha20 types -------------------------

instance Arbitrary (Key ChaCha20) where
  arbitrary = genEncodable

instance Arbitrary (Nounce ChaCha20) where
  arbitrary = genEncodable

instance Arbitrary (Counter ChaCha20) where
  arbitrary = le32ToCtr <$> arbitrary
    where le32ToCtr :: LE Word32 -> Counter ChaCha20
          le32ToCtr = fromIntegral

------------------ For XChaCha20 types -------------------------

instance Arbitrary (Key XChaCha20) where
  arbitrary = genEncodable

instance Arbitrary (Nounce XChaCha20) where
  arbitrary = genEncodable

instance Arbitrary (Counter XChaCha20) where
  arbitrary = le32ToCtr <$> arbitrary
    where le32ToCtr :: LE Word32 -> Counter XChaCha20
          le32ToCtr = fromIntegral

------------------ Arbitrary instances for Poly1305 -------------
instance Arbitrary Poly1305.R where
  arbitrary = genEncodable

instance Arbitrary Poly1305.S where
  arbitrary = genEncodable

instance Arbitrary Poly1305.Poly1305 where
  arbitrary = genEncodable

instance Arbitrary (Key Poly1305) where
  arbitrary = Poly1305.Key <$> arbitrary <*> arbitrary
