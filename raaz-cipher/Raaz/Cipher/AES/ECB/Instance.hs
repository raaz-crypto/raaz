{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (AES128 ECB Encryption) where
  type Recommended (AES128 ECB Encryption) = CPortable128 ECB Encryption
  type Reference (AES128 ECB Encryption) = Ref128 ECB Encryption

instance CryptoPrimitive (AES128 ECB Decryption) where
  type Recommended (AES128 ECB Decryption) = CPortable128 ECB Decryption
  type Reference (AES128 ECB Decryption) = Ref128 ECB Decryption

instance CryptoPrimitive (AES192 ECB Encryption) where
  type Recommended (AES192 ECB Encryption) = CPortable192 ECB Encryption
  type Reference (AES192 ECB Encryption) = Ref192 ECB Encryption

instance CryptoPrimitive (AES192 ECB Decryption) where
  type Recommended (AES192 ECB Decryption) = CPortable192 ECB Decryption
  type Reference (AES192 ECB Decryption) = Ref192 ECB Decryption

instance CryptoPrimitive (AES256 ECB Encryption) where
  type Recommended (AES256 ECB Encryption) = CPortable256 ECB Encryption
  type Reference (AES256 ECB Encryption) = Ref256 ECB Encryption

instance CryptoPrimitive (AES256 ECB Decryption) where
  type Recommended (AES256 ECB Decryption) = CPortable256 ECB Decryption
  type Reference (AES256 ECB Decryption) = Ref256 ECB Decryption

instance CipherGadget (Ref128 ECB)
instance CipherGadget (Ref192 ECB)
instance CipherGadget (Ref256 ECB)
instance CipherGadget (CPortable128 ECB)
instance CipherGadget (CPortable192 ECB)
instance CipherGadget (CPortable256 ECB)
