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


instance CryptoPrimitive (AES CBC KEY128) where
  type Recommended (AES CBC KEY128) = CGadget (AESOp CBC KEY128 EncryptMode)
  type Reference (AES CBC KEY128) = HGadget (AESOp CBC KEY128 EncryptMode)

instance CryptoPrimitive (AES CBC KEY192) where
  type Recommended (AES CBC KEY192) = CGadget (AESOp CBC KEY192 EncryptMode)
  type Reference (AES CBC KEY192) = HGadget (AESOp CBC KEY192 EncryptMode)

instance CryptoPrimitive (AES CBC KEY256) where
  type Recommended (AES CBC KEY256) = CGadget (AESOp CBC KEY256 EncryptMode)
  type Reference (AES CBC KEY256) = HGadget (AESOp CBC KEY256 EncryptMode)


instance CryptoInverse (CGadget (AESOp CBC KEY128 EncryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY128 EncryptMode)) = CGadget (AESOp CBC KEY128 DecryptMode)

instance CryptoInverse (CGadget (AESOp CBC KEY128 DecryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY128 DecryptMode)) = CGadget (AESOp CBC KEY128 EncryptMode)

instance CryptoInverse (CGadget (AESOp CBC KEY192 EncryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY192 EncryptMode)) = CGadget (AESOp CBC KEY192 DecryptMode)

instance CryptoInverse (CGadget (AESOp CBC KEY192 DecryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY192 DecryptMode)) = CGadget (AESOp CBC KEY192 EncryptMode)

instance CryptoInverse (CGadget (AESOp CBC KEY256 EncryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY256 EncryptMode)) = CGadget (AESOp CBC KEY256 DecryptMode)

instance CryptoInverse (CGadget (AESOp CBC KEY256 DecryptMode)) where
  type Inverse (CGadget (AESOp CBC KEY256 DecryptMode)) = CGadget (AESOp CBC KEY256 EncryptMode)



instance CryptoInverse (HGadget (AESOp CBC KEY128 EncryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY128 EncryptMode)) = HGadget (AESOp CBC KEY128 DecryptMode)

instance CryptoInverse (HGadget (AESOp CBC KEY128 DecryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY128 DecryptMode)) = HGadget (AESOp CBC KEY128 EncryptMode)

instance CryptoInverse (HGadget (AESOp CBC KEY192 EncryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY192 EncryptMode)) = HGadget (AESOp CBC KEY192 DecryptMode)

instance CryptoInverse (HGadget (AESOp CBC KEY192 DecryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY192 DecryptMode)) = HGadget (AESOp CBC KEY192 EncryptMode)

instance CryptoInverse (HGadget (AESOp CBC KEY256 EncryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY256 EncryptMode)) = HGadget (AESOp CBC KEY256 DecryptMode)

instance CryptoInverse (HGadget (AESOp CBC KEY256 DecryptMode)) where
  type Inverse (HGadget (AESOp CBC KEY256 DecryptMode)) = HGadget (AESOp CBC KEY256 EncryptMode)
