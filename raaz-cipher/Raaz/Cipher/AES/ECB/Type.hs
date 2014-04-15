{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types

import Raaz.Cipher.AES.Internal


instance Primitive (Cipher (AES ECB) k e) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (AES ECB) k e) = AESCxt k deriving Eq

instance Encrypt (Cipher (AES ECB) KEY128) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES ECB) KEY192) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES ECB) KEY256) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

type instance Key (Cipher (AES ECB) KEY128) EncryptMode = KEY128
type instance Key (Cipher (AES ECB) KEY128) DecryptMode = KEY128

type instance Key (Cipher (AES ECB) KEY192) EncryptMode = KEY192
type instance Key (Cipher (AES ECB) KEY192) DecryptMode = KEY192

type instance Key (Cipher (AES ECB) KEY256) EncryptMode = KEY256
type instance Key (Cipher (AES ECB) KEY256) DecryptMode = KEY256
