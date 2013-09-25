{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CBC.Type
import Raaz.Cipher.AES.CBC.Ref ()
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.Type

instance CryptoPrimitive (AES128 CBC Encryption) where
  type Recommended (AES128 CBC Encryption) = CPortable128 Encryption
  type Reference (AES128 CBC Encryption) = Ref128 Encryption

instance CryptoPrimitive (AES128 CBC Decryption) where
  type Recommended (AES128 CBC Decryption) = CPortable128 Decryption
  type Reference (AES128 CBC Decryption) = Ref128 Decryption

instance CryptoPrimitive (AES192 CBC Encryption) where
  type Recommended (AES192 CBC Encryption) = CPortable192 Encryption
  type Reference (AES192 CBC Encryption) = Ref192 Encryption

instance CryptoPrimitive (AES192 CBC Decryption) where
  type Recommended (AES192 CBC Decryption) = CPortable192 Decryption
  type Reference (AES192 CBC Decryption) = Ref192 Decryption

instance CryptoPrimitive (AES256 CBC Encryption) where
  type Recommended (AES256 CBC Encryption) = CPortable256 Encryption
  type Reference (AES256 CBC Encryption) = Ref256 Encryption

instance CryptoPrimitive (AES256 CBC Decryption) where
  type Recommended (AES256 CBC Decryption) = CPortable256 Decryption
  type Reference (AES256 CBC Decryption) = Ref256 Decryption
