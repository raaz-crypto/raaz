{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Type where

import           Data.ByteString              (ByteString)
import qualified Data.ByteString              as BS
import           Foreign.Storable
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString

import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Ref.Internal ()
import           Raaz.Cipher.AES.Internal


-- | Primitive for AES128 in CBC Mode
instance Primitive (AES128 CBC Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 CBC Encryption) = AES128EIV (KEY128, STATE)

instance Primitive (AES128 CBC Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 CBC Decryption) = AES128DIV (KEY128, STATE)

-- | Primitive for AES192 in CBC Mode
instance Primitive (AES192 CBC Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 CBC Encryption) = AES192EIV (KEY192, STATE)

instance Primitive (AES192 CBC Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 CBC Decryption) = AES192DIV (KEY192, STATE)

-- | Primitive for AES256 in CBC Mode
instance Primitive (AES256 CBC Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 CBC Encryption) = AES256EIV (KEY256, STATE)

instance Primitive (AES256 CBC Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 CBC Decryption) = AES256DIV (KEY256, STATE)

-- | First KEY then 128bit initialization vector
getIVCBC :: EndianStore k => ByteString -> k -> (k,STATE)
getIVCBC bs k = (fromByteString kbs,fromByteString ivbs)
  where
    (kbs,ivbs) = BS.splitAt (sizeOf k) bs

instance Initializable (AES128 CBC Encryption) where
  ivSize _ = BYTES (16 + 16)
  getIV src = AES128EIV $ getIVCBC src (undefined :: KEY128)

instance Initializable (AES128 CBC Decryption) where
  ivSize _ = BYTES (16 + 16)
  getIV src = AES128DIV $ getIVCBC src (undefined :: KEY128)

instance Initializable (AES192 CBC Encryption) where
  ivSize _ = BYTES (24 + 16)
  getIV src = AES192EIV $ getIVCBC src (undefined :: KEY192)

instance Initializable (AES192 CBC Decryption) where
  ivSize _ = BYTES (24 + 16)
  getIV src = AES192DIV $ getIVCBC src (undefined :: KEY192)

instance Initializable (AES256 CBC Encryption) where
  ivSize _ = BYTES (32 + 16)
  getIV src = AES256EIV $ getIVCBC src (undefined :: KEY256)

instance Initializable (AES256 CBC Decryption) where
  ivSize _ = BYTES (32 + 16)
  getIV src = AES256DIV $ getIVCBC src (undefined :: KEY256)
