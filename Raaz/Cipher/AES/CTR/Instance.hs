{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE DataKinds            #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref       ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal

---------------------- Gadget aliases ----------------------------

type CCTRG key = CAESGadget CTR key EncryptMode
type HCTRG key = HAESGadget CTR key EncryptMode

instance CryptoPrimitive (AES CTR KEY128) where
  type Recommended (AES CTR KEY128) = CCTRG KEY128
  type Reference (AES CTR KEY128) = HCTRG KEY128

instance CryptoPrimitive (AES CTR KEY192) where
  type Recommended (AES CTR KEY192) = CCTRG KEY192
  type Reference (AES CTR KEY192) = HCTRG KEY192

instance CryptoPrimitive (AES CTR KEY256) where
  type Recommended (AES CTR KEY256) = CCTRG KEY256
  type Reference (AES CTR KEY256) = HCTRG KEY256


instance CryptoInverse (CCTRG KEY128) where
  type Inverse (CCTRG KEY128) = CCTRG KEY128

instance CryptoInverse (CCTRG KEY192) where
  type Inverse (CCTRG KEY192) = CCTRG KEY192

instance CryptoInverse (CCTRG KEY256) where
  type Inverse (CCTRG KEY256) = CCTRG KEY256

instance CryptoInverse (HCTRG KEY128) where
  type Inverse (HCTRG KEY128) = HCTRG KEY128

instance CryptoInverse (HCTRG KEY192) where
  type Inverse (HCTRG KEY192) = HCTRG KEY192

instance CryptoInverse (HCTRG KEY256) where
  type Inverse (HCTRG KEY256) = HCTRG KEY256


instance StreamGadget (CCTRG KEY128)
instance StreamGadget (CCTRG KEY192)
instance StreamGadget (CCTRG KEY256)

instance StreamGadget (HCTRG KEY128)
instance StreamGadget (HCTRG KEY192)
instance StreamGadget (HCTRG KEY256)
