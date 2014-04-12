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

instance CryptoPrimitive (Cipher (AES CBC) KEY128 EncryptMode) where
  type Recommended (Cipher (AES CBC) KEY128 EncryptMode) = CGadget (Cipher (AES CBC) KEY128 EncryptMode)
  type Reference (Cipher (AES CBC) KEY128 EncryptMode) = HGadget (Cipher (AES CBC) KEY128 EncryptMode)

instance CryptoPrimitive (Cipher (AES CBC) KEY128 DecryptMode) where
  type Recommended (Cipher (AES CBC) KEY128 DecryptMode) = CGadget (Cipher (AES CBC) KEY128 DecryptMode)
  type Reference (Cipher (AES CBC) KEY128 DecryptMode) = HGadget (Cipher (AES CBC) KEY128 DecryptMode)

instance CryptoPrimitive (Cipher (AES CBC) KEY192 EncryptMode) where
  type Recommended (Cipher (AES CBC) KEY192 EncryptMode) = CGadget (Cipher (AES CBC) KEY192 EncryptMode)
  type Reference (Cipher (AES CBC) KEY192 EncryptMode) = HGadget (Cipher (AES CBC) KEY192 EncryptMode)

instance CryptoPrimitive (Cipher (AES CBC) KEY192 DecryptMode) where
  type Recommended (Cipher (AES CBC) KEY192 DecryptMode) = CGadget (Cipher (AES CBC) KEY192 DecryptMode)
  type Reference (Cipher (AES CBC) KEY192 DecryptMode) = HGadget (Cipher (AES CBC) KEY192 DecryptMode)

instance CryptoPrimitive (Cipher (AES CBC) KEY256 EncryptMode) where
  type Recommended (Cipher (AES CBC) KEY256 EncryptMode) = CGadget (Cipher (AES CBC) KEY256 EncryptMode)
  type Reference (Cipher (AES CBC) KEY256 EncryptMode) = HGadget (Cipher (AES CBC) KEY256 EncryptMode)

instance CryptoPrimitive (Cipher (AES CBC) KEY256 DecryptMode) where
  type Recommended (Cipher (AES CBC) KEY256 DecryptMode) = CGadget (Cipher (AES CBC) KEY256 DecryptMode)
  type Reference (Cipher (AES CBC) KEY256 DecryptMode) = HGadget (Cipher (AES CBC) KEY256 DecryptMode)
