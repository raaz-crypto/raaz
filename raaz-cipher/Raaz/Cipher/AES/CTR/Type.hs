{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Serialize
import Raaz.Types

import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Primitive (AES CTR k) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (AES CTR k) = AESCxt (k, STATE) deriving Eq

instance CryptoSerialize k => Cipher (AES CTR k) where
  cipherCxt = AESCxt

type instance Key (AES CTR k) = (k,STATE)
