{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Instance where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES.CBC.Ref       ()
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.Internal

---------------------- Type Aliases ----------------------

type HEncryptG key = HAESGadget CBC key EncryptMode
type HDecryptG key = HAESGadget CBC key DecryptMode


type CEncryptG key = CAESGadget CBC key EncryptMode
type CDecryptG key = CAESGadget CBC key DecryptMode

--------------------Instance declaration ------------------

instance CryptoPrimitive (AES CBC KEY128) where
  type Recommended (AES CBC KEY128) = CEncryptG KEY128
  type Reference (AES CBC KEY128) = HEncryptG KEY128

instance CryptoPrimitive (AES CBC KEY192) where
  type Recommended (AES CBC KEY192) = CEncryptG KEY192
  type Reference (AES CBC KEY192) = HEncryptG KEY192

instance CryptoPrimitive (AES CBC KEY256) where
  type Recommended (AES CBC KEY256) = CEncryptG KEY256
  type Reference (AES CBC KEY256) = HEncryptG KEY256


instance CryptoInverse (CEncryptG KEY128) where
  type Inverse (CEncryptG KEY128) = CDecryptG KEY128

instance CryptoInverse (CDecryptG KEY128) where
  type Inverse (CDecryptG KEY128) = CEncryptG KEY128

instance CryptoInverse (CEncryptG KEY192) where
  type Inverse (CEncryptG KEY192) = CDecryptG KEY192

instance CryptoInverse (CDecryptG KEY192) where
  type Inverse (CDecryptG KEY192) = CEncryptG KEY192

instance CryptoInverse (CEncryptG KEY256) where
  type Inverse (CEncryptG KEY256) = CDecryptG KEY256

instance CryptoInverse (CDecryptG KEY256) where
  type Inverse (CDecryptG KEY256) = CEncryptG KEY256



instance CryptoInverse (HEncryptG KEY128) where
  type Inverse (HEncryptG KEY128) = HDecryptG KEY128

instance CryptoInverse (HDecryptG KEY128) where
  type Inverse (HDecryptG KEY128) = HEncryptG KEY128

instance CryptoInverse (HEncryptG KEY192) where
  type Inverse (HEncryptG KEY192) = HDecryptG KEY192

instance CryptoInverse (HDecryptG KEY192) where
  type Inverse (HDecryptG KEY192) = HEncryptG KEY192

instance CryptoInverse (HEncryptG KEY256) where
  type Inverse (HEncryptG KEY256) = HDecryptG KEY256

instance CryptoInverse (HDecryptG KEY256) where
  type Inverse (HDecryptG KEY256) = HEncryptG KEY256
