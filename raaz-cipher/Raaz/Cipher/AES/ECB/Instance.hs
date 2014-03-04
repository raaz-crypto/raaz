{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher AES KEY128 ECB Encryption) where
  type Recommended (Cipher AES KEY128 ECB Encryption) = CGadget (Cipher AES KEY128 ECB Encryption)
  type Reference (Cipher AES KEY128 ECB Encryption) = HGadget (Cipher AES KEY128 ECB Encryption)

instance CryptoPrimitive (Cipher AES KEY128 ECB Decryption) where
  type Recommended (Cipher AES KEY128 ECB Decryption) = CGadget (Cipher AES KEY128 ECB Decryption)
  type Reference (Cipher AES KEY128 ECB Decryption) = HGadget (Cipher AES KEY128 ECB Decryption)

instance CryptoPrimitive (Cipher AES KEY192 ECB Encryption) where
  type Recommended (Cipher AES KEY192 ECB Encryption) = CGadget (Cipher AES KEY192 ECB Encryption)
  type Reference (Cipher AES KEY192 ECB Encryption) = HGadget (Cipher AES KEY192 ECB Encryption)

instance CryptoPrimitive (Cipher AES KEY192 ECB Decryption) where
  type Recommended (Cipher AES KEY192 ECB Decryption) = CGadget (Cipher AES KEY192 ECB Decryption)
  type Reference (Cipher AES KEY192 ECB Decryption) = HGadget (Cipher AES KEY192 ECB Decryption)

instance CryptoPrimitive (Cipher AES KEY256 ECB Encryption) where
  type Recommended (Cipher AES KEY256 ECB Encryption) = CGadget (Cipher AES KEY256 ECB Encryption)
  type Reference (Cipher AES KEY256 ECB Encryption) = HGadget (Cipher AES KEY256 ECB Encryption)

instance CryptoPrimitive (Cipher AES KEY256 ECB Decryption) where
  type Recommended (Cipher AES KEY256 ECB Decryption) = CGadget (Cipher AES KEY256 ECB Decryption)
  type Reference (Cipher AES KEY256 ECB Decryption) = HGadget (Cipher AES KEY256 ECB Decryption)

instance HasInverse (HGadget (Cipher AES KEY128 ECB Encryption)) where
  type Inverse (HGadget (Cipher AES KEY128 ECB Encryption)) = HGadget (Cipher AES KEY128 ECB Decryption)

instance HasInverse (HGadget (Cipher AES KEY128 ECB Decryption)) where
  type Inverse (HGadget (Cipher AES KEY128 ECB Decryption)) = HGadget (Cipher AES KEY128 ECB Encryption)

instance HasInverse (HGadget (Cipher AES KEY192 ECB Encryption)) where
  type Inverse (HGadget (Cipher AES KEY192 ECB Encryption)) = HGadget (Cipher AES KEY192 ECB Decryption)

instance HasInverse (HGadget (Cipher AES KEY192 ECB Decryption)) where
  type Inverse (HGadget (Cipher AES KEY192 ECB Decryption)) = HGadget (Cipher AES KEY192 ECB Encryption)

instance HasInverse (HGadget (Cipher AES KEY256 ECB Encryption)) where
  type Inverse (HGadget (Cipher AES KEY256 ECB Encryption)) = HGadget (Cipher AES KEY256 ECB Decryption)

instance HasInverse (HGadget (Cipher AES KEY256 ECB Decryption)) where
  type Inverse (HGadget (Cipher AES KEY256 ECB Decryption)) = HGadget (Cipher AES KEY256 ECB Encryption)

instance HasInverse (CGadget (Cipher AES KEY128 ECB Encryption)) where
  type Inverse (CGadget (Cipher AES KEY128 ECB Encryption)) = CGadget (Cipher AES KEY128 ECB Decryption)

instance HasInverse (CGadget (Cipher AES KEY128 ECB Decryption)) where
  type Inverse (CGadget (Cipher AES KEY128 ECB Decryption)) = CGadget (Cipher AES KEY128 ECB Encryption)

instance HasInverse (CGadget (Cipher AES KEY192 ECB Encryption)) where
  type Inverse (CGadget (Cipher AES KEY192 ECB Encryption)) = CGadget (Cipher AES KEY192 ECB Decryption)

instance HasInverse (CGadget (Cipher AES KEY192 ECB Decryption)) where
  type Inverse (CGadget (Cipher AES KEY192 ECB Decryption)) = CGadget (Cipher AES KEY192 ECB Encryption)

instance HasInverse (CGadget (Cipher AES KEY256 ECB Encryption)) where
  type Inverse (CGadget (Cipher AES KEY256 ECB Encryption)) = CGadget (Cipher AES KEY256 ECB Decryption)

instance HasInverse (CGadget (Cipher AES KEY256 ECB Decryption)) where
  type Inverse (CGadget (Cipher AES KEY256 ECB Decryption)) = CGadget (Cipher AES KEY256 ECB Encryption)
