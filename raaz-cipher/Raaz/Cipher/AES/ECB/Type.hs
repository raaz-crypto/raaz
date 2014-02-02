{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import           Foreign.Storable
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types

import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Ref.Internal ()
import           Raaz.Cipher.AES.Internal


-- | Primitive for AES128 in ECB Mode
instance Primitive (AES128 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 ECB Encryption) = AES128EIV ByteString

instance Primitive (AES128 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 ECB Decryption) = AES128DIV ByteString

-- | Primitive for AES192 in ECB Mode
instance Primitive (AES192 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 ECB Encryption) = AES192EIV ByteString

instance Primitive (AES192 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 ECB Decryption) = AES192DIV ByteString

-- | Primitive for AES256 in ECB Mode
instance Primitive (AES256 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 ECB Encryption) = AES256EIV ByteString

instance Primitive (AES256 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 ECB Decryption) = AES256DIV ByteString

instance Initializable (AES128 ECB Encryption) where
  ivSize _ = BYTES 16
  getIV bs = AES128EIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY128)

instance Initializable (AES128 ECB Decryption) where
  ivSize _ = BYTES 16
  getIV bs = AES128DIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY128)

instance Initializable (AES192 ECB Encryption) where
  ivSize _ = BYTES 24
  getIV bs = AES192EIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY192)

instance Initializable (AES192 ECB Decryption) where
  ivSize _ = BYTES 24
  getIV bs = AES192DIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY192)


instance Initializable (AES256 ECB Encryption) where
  ivSize _ = BYTES 32
  getIV bs = AES256EIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY256)


instance Initializable (AES256 ECB Decryption) where
  ivSize _ = BYTES 32
  getIV bs = AES256DIV (BS.take sz bs)
    where
      sz = sizeOf (undefined :: KEY256)
