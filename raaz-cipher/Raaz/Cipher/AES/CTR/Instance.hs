{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher (AES CTR) KEY128 Encryption) where
  type Recommended (Cipher (AES CTR) KEY128 Encryption) = CGadget (Cipher (AES CTR) KEY128 Encryption)
  type Reference (Cipher (AES CTR) KEY128 Encryption) = HGadget (Cipher (AES CTR) KEY128 Encryption)

instance CryptoPrimitive (Cipher (AES CTR) KEY128 Decryption) where
  type Recommended (Cipher (AES CTR) KEY128 Decryption) = CGadget (Cipher (AES CTR) KEY128 Decryption)
  type Reference (Cipher (AES CTR) KEY128 Decryption) = HGadget (Cipher (AES CTR) KEY128 Decryption)

instance CryptoPrimitive (Cipher (AES CTR) KEY192 Encryption) where
  type Recommended (Cipher (AES CTR) KEY192 Encryption) = CGadget (Cipher (AES CTR) KEY192 Encryption)
  type Reference (Cipher (AES CTR) KEY192 Encryption) = HGadget (Cipher (AES CTR) KEY192 Encryption)

instance CryptoPrimitive (Cipher (AES CTR) KEY192 Decryption) where
  type Recommended (Cipher (AES CTR) KEY192 Decryption) = CGadget (Cipher (AES CTR) KEY192 Decryption)
  type Reference (Cipher (AES CTR) KEY192 Decryption) = HGadget (Cipher (AES CTR) KEY192 Decryption)

instance CryptoPrimitive (Cipher (AES CTR) KEY256 Encryption) where
  type Recommended (Cipher (AES CTR) KEY256 Encryption) = CGadget (Cipher (AES CTR) KEY256 Encryption)
  type Reference (Cipher (AES CTR) KEY256 Encryption) = HGadget (Cipher (AES CTR) KEY256 Encryption)

instance CryptoPrimitive (Cipher (AES CTR) KEY256 Decryption) where
  type Recommended (Cipher (AES CTR) KEY256 Decryption) = CGadget (Cipher (AES CTR) KEY256 Decryption)
  type Reference (Cipher (AES CTR) KEY256 Decryption) = HGadget (Cipher (AES CTR) KEY256 Decryption)

instance StreamGadget (CGadget (Cipher (AES CTR) KEY128 Encryption))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY128 Decryption))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY192 Encryption))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY192 Decryption))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY256 Encryption))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY256 Decryption))

instance StreamGadget (HGadget (Cipher (AES CTR) KEY128 Encryption))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY128 Decryption))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY192 Encryption))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY192 Decryption))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY256 Encryption))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY256 Decryption))

instance HasInverse (HGadget (Cipher (AES CTR) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY128 Encryption)) = HGadget (Cipher (AES CTR) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (AES CTR) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY128 Decryption)) = HGadget (Cipher (AES CTR) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (AES CTR) KEY192 Encryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY192 Encryption)) = HGadget (Cipher (AES CTR) KEY192 Decryption)

instance HasInverse (HGadget (Cipher (AES CTR) KEY192 Decryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY192 Decryption)) = HGadget (Cipher (AES CTR) KEY192 Encryption)

instance HasInverse (HGadget (Cipher (AES CTR) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY256 Encryption)) = HGadget (Cipher (AES CTR) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (AES CTR) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (AES CTR) KEY256 Decryption)) = HGadget (Cipher (AES CTR) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY128 Encryption)) = CGadget (Cipher (AES CTR) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY128 Decryption)) = CGadget (Cipher (AES CTR) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY192 Encryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY192 Encryption)) = CGadget (Cipher (AES CTR) KEY192 Decryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY192 Decryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY192 Decryption)) = CGadget (Cipher (AES CTR) KEY192 Encryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY256 Encryption)) = CGadget (Cipher (AES CTR) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (AES CTR) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (AES CTR) KEY256 Decryption)) = CGadget (Cipher (AES CTR) KEY256 Encryption)
