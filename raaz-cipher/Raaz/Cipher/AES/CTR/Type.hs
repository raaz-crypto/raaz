{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Serialize
import Raaz.Core.Types

import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Primitive (AES CTR k) where
  blockSize _ = bytesQuot $ BYTES 1
  {-# INLINE blockSize #-}
  newtype Cxt (AES CTR k) = AESCxt (k, STATE) deriving Eq

instance CryptoSerialize k => Cipher (AES CTR k) where
  cipherCxt = AESCxt

type instance Key (AES CTR k) = (k,STATE)
