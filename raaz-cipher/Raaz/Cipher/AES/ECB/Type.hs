{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Serialize
import Raaz.Types

import Raaz.Cipher.AES.Internal


instance Primitive (AES ECB k) where
  blockSize _ = roundFloor $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (AES ECB k) = AESCxt k deriving Eq

instance CryptoSerialize k => Cipher (AES ECB k) where
  cipherCxt = AESCxt

type instance Key (AES ECB k) = k
