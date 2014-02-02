{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CBC.Ref ()
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (AES128 CBC Encryption) where
  type Recommended (AES128 CBC Encryption) = CPortable128 CBC Encryption
  type Reference (AES128 CBC Encryption) = Ref128 CBC Encryption

instance CryptoPrimitive (AES128 CBC Decryption) where
  type Recommended (AES128 CBC Decryption) = CPortable128 CBC Decryption
  type Reference (AES128 CBC Decryption) = Ref128 CBC Decryption

instance CryptoPrimitive (AES192 CBC Encryption) where
  type Recommended (AES192 CBC Encryption) = CPortable192 CBC Encryption
  type Reference (AES192 CBC Encryption) = Ref192 CBC Encryption

instance CryptoPrimitive (AES192 CBC Decryption) where
  type Recommended (AES192 CBC Decryption) = CPortable192 CBC Decryption
  type Reference (AES192 CBC Decryption) = Ref192 CBC Decryption

instance CryptoPrimitive (AES256 CBC Encryption) where
  type Recommended (AES256 CBC Encryption) = CPortable256 CBC Encryption
  type Reference (AES256 CBC Encryption) = Ref256 CBC Encryption

instance CryptoPrimitive (AES256 CBC Decryption) where
  type Recommended (AES256 CBC Decryption) = CPortable256 CBC Decryption
  type Reference (AES256 CBC Decryption) = Ref256 CBC Decryption

instance CipherGadget (Ref128 CBC)
instance CipherGadget (Ref192 CBC)
instance CipherGadget (Ref256 CBC)
instance CipherGadget (CPortable128 CBC)
instance CipherGadget (CPortable192 CBC)
instance CipherGadget (CPortable256 CBC)
