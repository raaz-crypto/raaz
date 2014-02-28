{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.ByteString

import Raaz.Cipher.AES.Ref.Internal ()
import Raaz.Cipher.AES.Internal


-- | Primitive for AES128 in ECB Mode
instance Primitive (AES128 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 ECB Encryption) = AES128EIV KEY128

instance Primitive (AES128 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 ECB Decryption) = AES128DIV KEY128

-- | Primitive for AES192 in ECB Mode
instance Primitive (AES192 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 ECB Encryption) = AES192EIV KEY192

instance Primitive (AES192 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 ECB Decryption) = AES192DIV KEY192

-- | Primitive for AES256 in ECB Mode
instance Primitive (AES256 ECB Encryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 ECB Encryption) = AES256EIV KEY256

instance Primitive (AES256 ECB Decryption) where
  blockSize _ = cryptoCoerce $ BITS (128 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 ECB Decryption) = AES256DIV KEY256

instance Initializable (AES128 ECB Encryption) where
  ivSize _ = BYTES 16
  getIV = AES128EIV . fromByteString

instance Initializable (AES128 ECB Decryption) where
  ivSize _ = BYTES 16
  getIV = AES128DIV . fromByteString

instance Initializable (AES192 ECB Encryption) where
  ivSize _ = BYTES 24
  getIV = AES192EIV . fromByteString

instance Initializable (AES192 ECB Decryption) where
  ivSize _ = BYTES 24
  getIV = AES192DIV . fromByteString

instance Initializable (AES256 ECB Encryption) where
  ivSize _ = BYTES 32
  getIV = AES256EIV . fromByteString

instance Initializable (AES256 ECB Decryption) where
  ivSize _ = BYTES 32
  getIV = AES256DIV . fromByteString
