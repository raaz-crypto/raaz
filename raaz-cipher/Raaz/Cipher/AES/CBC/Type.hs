{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Type where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Serialize
import Raaz.Core.Types

import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Primitive (AES CBC k) where
  blockSize _ = bytesQuot $ BYTES 16
  {-# INLINE blockSize #-}
  newtype Cxt (AES CBC k) = AESCxt (k, STATE) deriving Eq

instance CryptoSerialize k => Cipher (AES CBC k) where
  cipherCxt = AESCxt

type instance Key (AES CBC k) = (k,STATE)
