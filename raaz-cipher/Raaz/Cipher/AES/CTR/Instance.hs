{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref       ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal


instance CryptoPrimitive (AES CTR KEY128) where
  type Recommended (AES CTR KEY128) = CGadget (AESOp CTR KEY128 EncryptMode)
  type Reference (AES CTR KEY128) = HGadget (AESOp CTR KEY128 EncryptMode)

instance CryptoPrimitive (AES CTR KEY192) where
  type Recommended (AES CTR KEY192) = CGadget (AESOp CTR KEY192 EncryptMode)
  type Reference (AES CTR KEY192) = HGadget (AESOp CTR KEY192 EncryptMode)

instance CryptoPrimitive (AES CTR KEY256) where
  type Recommended (AES CTR KEY256) = CGadget (AESOp CTR KEY256 EncryptMode)
  type Reference (AES CTR KEY256) = HGadget (AESOp CTR KEY256 EncryptMode)


instance CryptoInverse (CGadget (AESOp CTR KEY128 EncryptMode)) where
  type Inverse (CGadget (AESOp CTR KEY128 EncryptMode)) = CGadget (AESOp CTR KEY128 EncryptMode)

instance CryptoInverse (CGadget (AESOp CTR KEY192 EncryptMode)) where
  type Inverse (CGadget (AESOp CTR KEY192 EncryptMode)) = CGadget (AESOp CTR KEY192 EncryptMode)

instance CryptoInverse (CGadget (AESOp CTR KEY256 EncryptMode)) where
  type Inverse (CGadget (AESOp CTR KEY256 EncryptMode)) = CGadget (AESOp CTR KEY256 EncryptMode)

instance CryptoInverse (HGadget (AESOp CTR KEY128 EncryptMode)) where
  type Inverse (HGadget (AESOp CTR KEY128 EncryptMode)) = HGadget (AESOp CTR KEY128 EncryptMode)

instance CryptoInverse (HGadget (AESOp CTR KEY192 EncryptMode)) where
  type Inverse (HGadget (AESOp CTR KEY192 EncryptMode)) = HGadget (AESOp CTR KEY192 EncryptMode)

instance CryptoInverse (HGadget (AESOp CTR KEY256 EncryptMode)) where
  type Inverse (HGadget (AESOp CTR KEY256 EncryptMode)) = HGadget (AESOp CTR KEY256 EncryptMode)


instance StreamGadget (CGadget (AESOp CTR KEY128 EncryptMode))
instance StreamGadget (CGadget (AESOp CTR KEY192 EncryptMode))
instance StreamGadget (CGadget (AESOp CTR KEY256 EncryptMode))

instance StreamGadget (HGadget (AESOp CTR KEY128 EncryptMode))
instance StreamGadget (HGadget (AESOp CTR KEY192 EncryptMode))
instance StreamGadget (HGadget (AESOp CTR KEY256 EncryptMode))
