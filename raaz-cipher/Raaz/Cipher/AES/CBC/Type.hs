{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Type where

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types

import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Primitive (Cipher (AES CBC) k e) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (AES CBC) k e) = AESCxt (k, STATE) deriving Eq

instance Encrypt (Cipher (AES CBC) KEY128) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES CBC) KEY192) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES CBC) KEY256) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

type instance Key (Cipher (AES CBC) KEY128 EncryptMode) = (KEY128,STATE)
type instance Key (Cipher (AES CBC) KEY128 DecryptMode) = (KEY128,STATE)

type instance Key (Cipher (AES CBC) KEY192 EncryptMode) = (KEY192,STATE)
type instance Key (Cipher (AES CBC) KEY192 DecryptMode) = (KEY192,STATE)

type instance Key (Cipher (AES CBC) KEY256 EncryptMode) = (KEY256,STATE)
type instance Key (Cipher (AES CBC) KEY256 DecryptMode) = (KEY256,STATE)
