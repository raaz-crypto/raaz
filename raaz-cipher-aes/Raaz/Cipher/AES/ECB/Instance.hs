{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.Type

instance CryptoPrimitive (AES128 ECB Encryption) where
  type Recommended (AES128 ECB Encryption) = CPortable128 Encryption
  type Reference (AES128 ECB Encryption) = Ref128 Encryption

instance CryptoPrimitive (AES128 ECB Decryption) where
  type Recommended (AES128 ECB Decryption) = CPortable128 Decryption
  type Reference (AES128 ECB Decryption) = Ref128 Decryption

instance CryptoPrimitive (AES192 ECB Encryption) where
  type Recommended (AES192 ECB Encryption) = CPortable192 Encryption
  type Reference (AES192 ECB Encryption) = Ref192 Encryption

instance CryptoPrimitive (AES192 ECB Decryption) where
  type Recommended (AES192 ECB Decryption) = CPortable192 Decryption
  type Reference (AES192 ECB Decryption) = Ref192 Decryption

instance CryptoPrimitive (AES256 ECB Encryption) where
  type Recommended (AES256 ECB Encryption) = CPortable256 Encryption
  type Reference (AES256 ECB Encryption) = Ref256 Encryption

instance CryptoPrimitive (AES256 ECB Decryption) where
  type Recommended (AES256 ECB Decryption) = CPortable256 Decryption
  type Reference (AES256 ECB Decryption) = Ref256 Decryption
