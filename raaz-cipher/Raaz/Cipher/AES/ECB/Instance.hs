{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher (AES ECB) KEY128 Encryption) where
  type Recommended (Cipher (AES ECB) KEY128 Encryption) = CGadget (Cipher (AES ECB) KEY128 Encryption)
  type Reference (Cipher (AES ECB) KEY128 Encryption) = HGadget (Cipher (AES ECB) KEY128 Encryption)

instance CryptoPrimitive (Cipher (AES ECB) KEY128 Decryption) where
  type Recommended (Cipher (AES ECB) KEY128 Decryption) = CGadget (Cipher (AES ECB) KEY128 Decryption)
  type Reference (Cipher (AES ECB) KEY128 Decryption) = HGadget (Cipher (AES ECB) KEY128 Decryption)

instance CryptoPrimitive (Cipher (AES ECB) KEY192 Encryption) where
  type Recommended (Cipher (AES ECB) KEY192 Encryption) = CGadget (Cipher (AES ECB) KEY192 Encryption)
  type Reference (Cipher (AES ECB) KEY192 Encryption) = HGadget (Cipher (AES ECB) KEY192 Encryption)

instance CryptoPrimitive (Cipher (AES ECB) KEY192 Decryption) where
  type Recommended (Cipher (AES ECB) KEY192 Decryption) = CGadget (Cipher (AES ECB) KEY192 Decryption)
  type Reference (Cipher (AES ECB) KEY192 Decryption) = HGadget (Cipher (AES ECB) KEY192 Decryption)

instance CryptoPrimitive (Cipher (AES ECB) KEY256 Encryption) where
  type Recommended (Cipher (AES ECB) KEY256 Encryption) = CGadget (Cipher (AES ECB) KEY256 Encryption)
  type Reference (Cipher (AES ECB) KEY256 Encryption) = HGadget (Cipher (AES ECB) KEY256 Encryption)

instance CryptoPrimitive (Cipher (AES ECB) KEY256 Decryption) where
  type Recommended (Cipher (AES ECB) KEY256 Decryption) = CGadget (Cipher (AES ECB) KEY256 Decryption)
  type Reference (Cipher (AES ECB) KEY256 Decryption) = HGadget (Cipher (AES ECB) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY128 Encryption)) = HGadget (Cipher (AES ECB) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY128 Decryption)) = HGadget (Cipher (AES ECB) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY192 Encryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY192 Encryption)) = HGadget (Cipher (AES ECB) KEY192 Decryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY192 Decryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY192 Decryption)) = HGadget (Cipher (AES ECB) KEY192 Encryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY256 Encryption)) = HGadget (Cipher (AES ECB) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (AES ECB) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (AES ECB) KEY256 Decryption)) = HGadget (Cipher (AES ECB) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY128 Encryption)) = CGadget (Cipher (AES ECB) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY128 Decryption)) = CGadget (Cipher (AES ECB) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY192 Encryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY192 Encryption)) = CGadget (Cipher (AES ECB) KEY192 Decryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY192 Decryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY192 Decryption)) = CGadget (Cipher (AES ECB) KEY192 Encryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY256 Encryption)) = CGadget (Cipher (AES ECB) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (AES ECB) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (AES ECB) KEY256 Decryption)) = CGadget (Cipher (AES ECB) KEY256 Encryption)
