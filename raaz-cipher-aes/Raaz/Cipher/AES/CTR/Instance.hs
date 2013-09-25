{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Type
import Raaz.Cipher.AES.CTR.Ref ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Type

instance CryptoPrimitive (AES128 CTR Encryption) where
  type Recommended (AES128 CTR Encryption) = CPortable128 Encryption
  type Reference (AES128 CTR Encryption) = Ref128 Encryption

instance CryptoPrimitive (AES128 CTR Decryption) where
  type Recommended (AES128 CTR Decryption) = CPortable128 Decryption
  type Reference (AES128 CTR Decryption) = Ref128 Decryption

instance CryptoPrimitive (AES192 CTR Encryption) where
  type Recommended (AES192 CTR Encryption) = CPortable192 Encryption
  type Reference (AES192 CTR Encryption) = Ref192 Encryption

instance CryptoPrimitive (AES192 CTR Decryption) where
  type Recommended (AES192 CTR Decryption) = CPortable192 Decryption
  type Reference (AES192 CTR Decryption) = Ref192 Decryption

instance CryptoPrimitive (AES256 CTR Encryption) where
  type Recommended (AES256 CTR Encryption) = CPortable256 Encryption
  type Reference (AES256 CTR Encryption) = Ref256 Encryption

instance CryptoPrimitive (AES256 CTR Decryption) where
  type Recommended (AES256 CTR Decryption) = CPortable256 Decryption
  type Reference (AES256 CTR Decryption) = Ref256 Decryption
