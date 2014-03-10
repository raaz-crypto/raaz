{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Type where

import qualified Data.ByteString              as BS
import           Foreign.Storable             (sizeOf)
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString

import           Raaz.Cipher.AES.Internal


instance Primitive (Cipher (AES CBC) k e) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (AES CBC) k e) = AESCxt (k, STATE) deriving Eq

instance EndianStore k => Initializable (Cipher (AES CBC) k e) where
  cxtSize _ = BYTES (ksz + ssz)
    where
      ksz = sizeOf (undefined :: k)
      ssz = sizeOf (undefined :: STATE)
  {-# INLINE cxtSize #-}
  getCxt = AESCxt . getCxtCBC
    where
      getCxtCBC bs = (k,fromByteString ivbs)
        where
          k = fromByteString kbs
          (kbs,ivbs) = BS.splitAt (sizeOf k) bs
