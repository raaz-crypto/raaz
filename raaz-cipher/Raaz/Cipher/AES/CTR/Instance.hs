{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher (AES CTR) KEY128 EncryptMode) where
  type Recommended (Cipher (AES CTR) KEY128 EncryptMode) = CGadget (Cipher (AES CTR) KEY128 EncryptMode)
  type Reference (Cipher (AES CTR) KEY128 EncryptMode) = HGadget (Cipher (AES CTR) KEY128 EncryptMode)

instance CryptoPrimitive (Cipher (AES CTR) KEY128 DecryptMode) where
  type Recommended (Cipher (AES CTR) KEY128 DecryptMode) = CGadget (Cipher (AES CTR) KEY128 DecryptMode)
  type Reference (Cipher (AES CTR) KEY128 DecryptMode) = HGadget (Cipher (AES CTR) KEY128 DecryptMode)

instance CryptoPrimitive (Cipher (AES CTR) KEY192 EncryptMode) where
  type Recommended (Cipher (AES CTR) KEY192 EncryptMode) = CGadget (Cipher (AES CTR) KEY192 EncryptMode)
  type Reference (Cipher (AES CTR) KEY192 EncryptMode) = HGadget (Cipher (AES CTR) KEY192 EncryptMode)

instance CryptoPrimitive (Cipher (AES CTR) KEY192 DecryptMode) where
  type Recommended (Cipher (AES CTR) KEY192 DecryptMode) = CGadget (Cipher (AES CTR) KEY192 DecryptMode)
  type Reference (Cipher (AES CTR) KEY192 DecryptMode) = HGadget (Cipher (AES CTR) KEY192 DecryptMode)

instance CryptoPrimitive (Cipher (AES CTR) KEY256 EncryptMode) where
  type Recommended (Cipher (AES CTR) KEY256 EncryptMode) = CGadget (Cipher (AES CTR) KEY256 EncryptMode)
  type Reference (Cipher (AES CTR) KEY256 EncryptMode) = HGadget (Cipher (AES CTR) KEY256 EncryptMode)

instance CryptoPrimitive (Cipher (AES CTR) KEY256 DecryptMode) where
  type Recommended (Cipher (AES CTR) KEY256 DecryptMode) = CGadget (Cipher (AES CTR) KEY256 DecryptMode)
  type Reference (Cipher (AES CTR) KEY256 DecryptMode) = HGadget (Cipher (AES CTR) KEY256 DecryptMode)

instance StreamGadget (CGadget (Cipher (AES CTR) KEY128 EncryptMode))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY128 DecryptMode))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY192 EncryptMode))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY192 DecryptMode))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY256 EncryptMode))
instance StreamGadget (CGadget (Cipher (AES CTR) KEY256 DecryptMode))

instance StreamGadget (HGadget (Cipher (AES CTR) KEY128 EncryptMode))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY128 DecryptMode))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY192 EncryptMode))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY192 DecryptMode))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY256 EncryptMode))
instance StreamGadget (HGadget (Cipher (AES CTR) KEY256 DecryptMode))
