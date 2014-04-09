{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import qualified Data.ByteString              as BS
import           Foreign.Storable             (sizeOf)
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString

import           Raaz.Cipher.AES.Block.Internal
import           Raaz.Cipher.AES.Internal


instance Primitive (Cipher (AES CTR) k e) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (AES CTR) k e) = AESCxt (k, STATE) deriving Eq

instance EndianStore k => Initializable (Cipher (AES CTR) k e) where
  cxtSize _ = BYTES (ksz + ssz)
    where
      ksz = sizeOf (undefined :: k)
      ssz = sizeOf (undefined :: STATE)
  {-# INLINE cxtSize #-}
  getCxt = AESCxt . getCxtCTR
    where
      getCxtCTR bs = (k,fromByteString ivbs)
        where
          k = fromByteString kbs
          (kbs,ivbs) = BS.splitAt (sizeOf k) bs

instance Encrypt (Cipher (AES CTR) KEY128) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES CTR) KEY192) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

instance Encrypt (Cipher (AES CTR) KEY256) where
  encryptCxt = AESCxt
  decryptCxt = AESCxt

type instance Key (Cipher (AES CTR) KEY128) EncryptMode = (KEY128,STATE)
type instance Key (Cipher (AES CTR) KEY128) DecryptMode = (KEY128,STATE)

type instance Key (Cipher (AES CTR) KEY192) EncryptMode = (KEY192,STATE)
type instance Key (Cipher (AES CTR) KEY192) DecryptMode = (KEY192,STATE)

type instance Key (Cipher (AES CTR) KEY256) EncryptMode = (KEY256,STATE)
type instance Key (Cipher (AES CTR) KEY256) DecryptMode = (KEY256,STATE)
