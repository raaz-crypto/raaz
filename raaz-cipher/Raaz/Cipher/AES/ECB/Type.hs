{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Serialize
import Raaz.Core.Types

import Raaz.Cipher.AES.Internal


instance Primitive (AES ECB k) where
  blockSize _ = bytesQuot $ BYTES 16

  {-# INLINE blockSize #-}
  newtype Cxt (AES ECB k) = AESCxt k deriving Eq

instance CryptoSerialize k => Cipher (AES ECB k) where
  cipherCxt = AESCxt

type instance Key (AES ECB k) = k
