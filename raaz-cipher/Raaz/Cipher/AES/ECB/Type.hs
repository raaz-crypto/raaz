{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Foreign.Storable             (sizeOf)
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.ByteString

import Raaz.Cipher.AES.Internal


instance Primitive (Cipher AES k ECB e) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher AES k ECB e) = AESCxt k deriving Eq

instance EndianStore k => Initializable (Cipher AES k ECB e) where
  ivSize _ = BYTES ksz
    where
      ksz = sizeOf (undefined :: k)
  {-# INLINE ivSize #-}
  getIV = AESCxt . fromByteString
