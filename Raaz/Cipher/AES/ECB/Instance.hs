{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Instance where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (AES ECB KEY128) where
  type Recommended (AES ECB KEY128) = CGadget (AESOp ECB KEY128 EncryptMode)
  type Reference (AES ECB KEY128) = HGadget (AESOp ECB KEY128 EncryptMode)

instance CryptoPrimitive (AES ECB KEY192) where
  type Recommended (AES ECB KEY192) = CGadget (AESOp ECB KEY192 EncryptMode)
  type Reference (AES ECB KEY192) = HGadget (AESOp ECB KEY192 EncryptMode)

instance CryptoPrimitive (AES ECB KEY256) where
  type Recommended (AES ECB KEY256) = CGadget (AESOp ECB KEY256 EncryptMode)
  type Reference (AES ECB KEY256) = HGadget (AESOp ECB KEY256 EncryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY128 EncryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY128 EncryptMode)) = CGadget (AESOp ECB KEY128 DecryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY128 DecryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY128 DecryptMode)) = CGadget (AESOp ECB KEY128 EncryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY192 EncryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY192 EncryptMode)) = CGadget (AESOp ECB KEY192 DecryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY192 DecryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY192 DecryptMode)) = CGadget (AESOp ECB KEY192 EncryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY256 EncryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY256 EncryptMode)) = CGadget (AESOp ECB KEY256 DecryptMode)

instance CryptoInverse (CGadget (AESOp ECB KEY256 DecryptMode)) where
  type Inverse (CGadget (AESOp ECB KEY256 DecryptMode)) = CGadget (AESOp ECB KEY256 EncryptMode)


instance CryptoInverse (HGadget (AESOp ECB KEY128 EncryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY128 EncryptMode)) = HGadget (AESOp ECB KEY128 DecryptMode)

instance CryptoInverse (HGadget (AESOp ECB KEY128 DecryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY128 DecryptMode)) = HGadget (AESOp ECB KEY128 EncryptMode)

instance CryptoInverse (HGadget (AESOp ECB KEY192 EncryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY192 EncryptMode)) = HGadget (AESOp ECB KEY192 DecryptMode)

instance CryptoInverse (HGadget (AESOp ECB KEY192 DecryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY192 DecryptMode)) = HGadget (AESOp ECB KEY192 EncryptMode)

instance CryptoInverse (HGadget (AESOp ECB KEY256 EncryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY256 EncryptMode)) = HGadget (AESOp ECB KEY256 DecryptMode)

instance CryptoInverse (HGadget (AESOp ECB KEY256 DecryptMode)) where
  type Inverse (HGadget (AESOp ECB KEY256 DecryptMode)) = HGadget (AESOp ECB KEY256 EncryptMode)
