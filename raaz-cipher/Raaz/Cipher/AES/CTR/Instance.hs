{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (AES128 CTR Encryption) where
  type Recommended (AES128 CTR Encryption) = CPortable128 CTR Encryption
  type Reference (AES128 CTR Encryption) = Ref128 CTR Encryption

instance CryptoPrimitive (AES128 CTR Decryption) where
  type Recommended (AES128 CTR Decryption) = CPortable128 CTR Decryption
  type Reference (AES128 CTR Decryption) = Ref128 CTR Decryption

instance CryptoPrimitive (AES192 CTR Encryption) where
  type Recommended (AES192 CTR Encryption) = CPortable192 CTR Encryption
  type Reference (AES192 CTR Encryption) = Ref192 CTR Encryption

instance CryptoPrimitive (AES192 CTR Decryption) where
  type Recommended (AES192 CTR Decryption) = CPortable192 CTR Decryption
  type Reference (AES192 CTR Decryption) = Ref192 CTR Decryption

instance CryptoPrimitive (AES256 CTR Encryption) where
  type Recommended (AES256 CTR Encryption) = CPortable256 CTR Encryption
  type Reference (AES256 CTR Encryption) = Ref256 CTR Encryption

instance CryptoPrimitive (AES256 CTR Decryption) where
  type Recommended (AES256 CTR Decryption) = CPortable256 CTR Decryption
  type Reference (AES256 CTR Decryption) = Ref256 CTR Decryption


instance CipherGadget (Ref128 CTR)
instance CipherGadget (Ref192 CTR)
instance CipherGadget (Ref256 CTR)
instance CipherGadget (CPortable128 CTR)
instance CipherGadget (CPortable192 CTR)
instance CipherGadget (CPortable256 CTR)

instance StreamGadget (Ref128 CTR Encryption)
instance StreamGadget (Ref192 CTR Encryption)
instance StreamGadget (Ref256 CTR Encryption)
instance StreamGadget (CPortable128 CTR Encryption)
instance StreamGadget (CPortable192 CTR Encryption)
instance StreamGadget (CPortable256 CTR Encryption)

instance StreamGadget (Ref128 CTR Decryption)
instance StreamGadget (Ref192 CTR Decryption)
instance StreamGadget (Ref256 CTR Decryption)
instance StreamGadget (CPortable128 CTR Decryption)
instance StreamGadget (CPortable192 CTR Decryption)
instance StreamGadget (CPortable256 CTR Decryption)
