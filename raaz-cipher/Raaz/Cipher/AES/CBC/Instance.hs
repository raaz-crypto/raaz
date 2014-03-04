{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CBC.Ref ()
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher AES KEY128 CBC Encryption) where
  type Recommended (Cipher AES KEY128 CBC Encryption) = CGadget (Cipher AES KEY128 CBC Encryption)
  type Reference (Cipher AES KEY128 CBC Encryption) = HGadget (Cipher AES KEY128 CBC Encryption)

instance CryptoPrimitive (Cipher AES KEY128 CBC Decryption) where
  type Recommended (Cipher AES KEY128 CBC Decryption) = CGadget (Cipher AES KEY128 CBC Decryption)
  type Reference (Cipher AES KEY128 CBC Decryption) = HGadget (Cipher AES KEY128 CBC Decryption)

instance CryptoPrimitive (Cipher AES KEY192 CBC Encryption) where
  type Recommended (Cipher AES KEY192 CBC Encryption) = CGadget (Cipher AES KEY192 CBC Encryption)
  type Reference (Cipher AES KEY192 CBC Encryption) = HGadget (Cipher AES KEY192 CBC Encryption)

instance CryptoPrimitive (Cipher AES KEY192 CBC Decryption) where
  type Recommended (Cipher AES KEY192 CBC Decryption) = CGadget (Cipher AES KEY192 CBC Decryption)
  type Reference (Cipher AES KEY192 CBC Decryption) = HGadget (Cipher AES KEY192 CBC Decryption)

instance CryptoPrimitive (Cipher AES KEY256 CBC Encryption) where
  type Recommended (Cipher AES KEY256 CBC Encryption) = CGadget (Cipher AES KEY256 CBC Encryption)
  type Reference (Cipher AES KEY256 CBC Encryption) = HGadget (Cipher AES KEY256 CBC Encryption)

instance CryptoPrimitive (Cipher AES KEY256 CBC Decryption) where
  type Recommended (Cipher AES KEY256 CBC Decryption) = CGadget (Cipher AES KEY256 CBC Decryption)
  type Reference (Cipher AES KEY256 CBC Decryption) = HGadget (Cipher AES KEY256 CBC Decryption)

instance HasInverse (HGadget (Cipher AES KEY128 CBC Encryption)) where
  type Inverse (HGadget (Cipher AES KEY128 CBC Encryption)) = HGadget (Cipher AES KEY128 CBC Decryption)

instance HasInverse (HGadget (Cipher AES KEY128 CBC Decryption)) where
  type Inverse (HGadget (Cipher AES KEY128 CBC Decryption)) = HGadget (Cipher AES KEY128 CBC Encryption)

instance HasInverse (HGadget (Cipher AES KEY192 CBC Encryption)) where
  type Inverse (HGadget (Cipher AES KEY192 CBC Encryption)) = HGadget (Cipher AES KEY192 CBC Decryption)

instance HasInverse (HGadget (Cipher AES KEY192 CBC Decryption)) where
  type Inverse (HGadget (Cipher AES KEY192 CBC Decryption)) = HGadget (Cipher AES KEY192 CBC Encryption)

instance HasInverse (HGadget (Cipher AES KEY256 CBC Encryption)) where
  type Inverse (HGadget (Cipher AES KEY256 CBC Encryption)) = HGadget (Cipher AES KEY256 CBC Decryption)

instance HasInverse (HGadget (Cipher AES KEY256 CBC Decryption)) where
  type Inverse (HGadget (Cipher AES KEY256 CBC Decryption)) = HGadget (Cipher AES KEY256 CBC Encryption)

instance HasInverse (CGadget (Cipher AES KEY128 CBC Encryption)) where
  type Inverse (CGadget (Cipher AES KEY128 CBC Encryption)) = CGadget (Cipher AES KEY128 CBC Decryption)

instance HasInverse (CGadget (Cipher AES KEY128 CBC Decryption)) where
  type Inverse (CGadget (Cipher AES KEY128 CBC Decryption)) = CGadget (Cipher AES KEY128 CBC Encryption)

instance HasInverse (CGadget (Cipher AES KEY192 CBC Encryption)) where
  type Inverse (CGadget (Cipher AES KEY192 CBC Encryption)) = CGadget (Cipher AES KEY192 CBC Decryption)

instance HasInverse (CGadget (Cipher AES KEY192 CBC Decryption)) where
  type Inverse (CGadget (Cipher AES KEY192 CBC Decryption)) = CGadget (Cipher AES KEY192 CBC Encryption)

instance HasInverse (CGadget (Cipher AES KEY256 CBC Encryption)) where
  type Inverse (CGadget (Cipher AES KEY256 CBC Encryption)) = CGadget (Cipher AES KEY256 CBC Decryption)

instance HasInverse (CGadget (Cipher AES KEY256 CBC Decryption)) where
  type Inverse (CGadget (Cipher AES KEY256 CBC Decryption)) = CGadget (Cipher AES KEY256 CBC Encryption)
