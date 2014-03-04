{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR.Ref ()
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher AES KEY128 CTR Encryption) where
  type Recommended (Cipher AES KEY128 CTR Encryption) = CGadget (Cipher AES KEY128 CTR Encryption)
  type Reference (Cipher AES KEY128 CTR Encryption) = HGadget (Cipher AES KEY128 CTR Encryption)

instance CryptoPrimitive (Cipher AES KEY128 CTR Decryption) where
  type Recommended (Cipher AES KEY128 CTR Decryption) = CGadget (Cipher AES KEY128 CTR Decryption)
  type Reference (Cipher AES KEY128 CTR Decryption) = HGadget (Cipher AES KEY128 CTR Decryption)

instance CryptoPrimitive (Cipher AES KEY192 CTR Encryption) where
  type Recommended (Cipher AES KEY192 CTR Encryption) = CGadget (Cipher AES KEY192 CTR Encryption)
  type Reference (Cipher AES KEY192 CTR Encryption) = HGadget (Cipher AES KEY192 CTR Encryption)

instance CryptoPrimitive (Cipher AES KEY192 CTR Decryption) where
  type Recommended (Cipher AES KEY192 CTR Decryption) = CGadget (Cipher AES KEY192 CTR Decryption)
  type Reference (Cipher AES KEY192 CTR Decryption) = HGadget (Cipher AES KEY192 CTR Decryption)

instance CryptoPrimitive (Cipher AES KEY256 CTR Encryption) where
  type Recommended (Cipher AES KEY256 CTR Encryption) = CGadget (Cipher AES KEY256 CTR Encryption)
  type Reference (Cipher AES KEY256 CTR Encryption) = HGadget (Cipher AES KEY256 CTR Encryption)

instance CryptoPrimitive (Cipher AES KEY256 CTR Decryption) where
  type Recommended (Cipher AES KEY256 CTR Decryption) = CGadget (Cipher AES KEY256 CTR Decryption)
  type Reference (Cipher AES KEY256 CTR Decryption) = HGadget (Cipher AES KEY256 CTR Decryption)

instance StreamGadget (CGadget (Cipher AES KEY128 CTR Encryption))
instance StreamGadget (CGadget (Cipher AES KEY128 CTR Decryption))
instance StreamGadget (CGadget (Cipher AES KEY192 CTR Encryption))
instance StreamGadget (CGadget (Cipher AES KEY192 CTR Decryption))
instance StreamGadget (CGadget (Cipher AES KEY256 CTR Encryption))
instance StreamGadget (CGadget (Cipher AES KEY256 CTR Decryption))

instance StreamGadget (HGadget (Cipher AES KEY128 CTR Encryption))
instance StreamGadget (HGadget (Cipher AES KEY128 CTR Decryption))
instance StreamGadget (HGadget (Cipher AES KEY192 CTR Encryption))
instance StreamGadget (HGadget (Cipher AES KEY192 CTR Decryption))
instance StreamGadget (HGadget (Cipher AES KEY256 CTR Encryption))
instance StreamGadget (HGadget (Cipher AES KEY256 CTR Decryption))

instance HasInverse (HGadget (Cipher AES KEY128 CTR Encryption)) where
  type Inverse (HGadget (Cipher AES KEY128 CTR Encryption)) = HGadget (Cipher AES KEY128 CTR Decryption)

instance HasInverse (HGadget (Cipher AES KEY128 CTR Decryption)) where
  type Inverse (HGadget (Cipher AES KEY128 CTR Decryption)) = HGadget (Cipher AES KEY128 CTR Encryption)

instance HasInverse (HGadget (Cipher AES KEY192 CTR Encryption)) where
  type Inverse (HGadget (Cipher AES KEY192 CTR Encryption)) = HGadget (Cipher AES KEY192 CTR Decryption)

instance HasInverse (HGadget (Cipher AES KEY192 CTR Decryption)) where
  type Inverse (HGadget (Cipher AES KEY192 CTR Decryption)) = HGadget (Cipher AES KEY192 CTR Encryption)

instance HasInverse (HGadget (Cipher AES KEY256 CTR Encryption)) where
  type Inverse (HGadget (Cipher AES KEY256 CTR Encryption)) = HGadget (Cipher AES KEY256 CTR Decryption)

instance HasInverse (HGadget (Cipher AES KEY256 CTR Decryption)) where
  type Inverse (HGadget (Cipher AES KEY256 CTR Decryption)) = HGadget (Cipher AES KEY256 CTR Encryption)

instance HasInverse (CGadget (Cipher AES KEY128 CTR Encryption)) where
  type Inverse (CGadget (Cipher AES KEY128 CTR Encryption)) = CGadget (Cipher AES KEY128 CTR Decryption)

instance HasInverse (CGadget (Cipher AES KEY128 CTR Decryption)) where
  type Inverse (CGadget (Cipher AES KEY128 CTR Decryption)) = CGadget (Cipher AES KEY128 CTR Encryption)

instance HasInverse (CGadget (Cipher AES KEY192 CTR Encryption)) where
  type Inverse (CGadget (Cipher AES KEY192 CTR Encryption)) = CGadget (Cipher AES KEY192 CTR Decryption)

instance HasInverse (CGadget (Cipher AES KEY192 CTR Decryption)) where
  type Inverse (CGadget (Cipher AES KEY192 CTR Decryption)) = CGadget (Cipher AES KEY192 CTR Encryption)

instance HasInverse (CGadget (Cipher AES KEY256 CTR Encryption)) where
  type Inverse (CGadget (Cipher AES KEY256 CTR Encryption)) = CGadget (Cipher AES KEY256 CTR Decryption)

instance HasInverse (CGadget (Cipher AES KEY256 CTR Decryption)) where
  type Inverse (CGadget (Cipher AES KEY256 CTR Decryption)) = CGadget (Cipher AES KEY256 CTR Encryption)
