{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types

import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Ref.Block ()
import           Raaz.Cipher.AES.Type


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
  getIV = AES128EIV

instance Initializable (AES128 ECB Decryption) where
  getIV = AES128DIV

instance Initializable (AES192 ECB Encryption) where
  getIV = AES192EIV

instance Initializable (AES192 ECB Decryption) where
  getIV = AES192DIV

instance Initializable (AES256 ECB Encryption) where
  getIV = AES256EIV

instance Initializable (AES256 ECB Decryption) where
  getIV = AES256DIV

-- | Reference Implementation for AES128 in ECB Mode
data Ref128 (s :: Stage) = Ref128 (CryptoCell Expanded128)

-- | Reference Implementation for AES192 in ECB Mode
data Ref192 (s :: Stage) = Ref192 (CryptoCell Expanded192)

-- | Reference Implementation for AES256 in ECB Mode
data Ref256 (s :: Stage) = Ref256 (CryptoCell Expanded256)

-- | CPortable Implementation for AES128 in ECB Mode
data CPortable128 (s :: Stage) = CPortable128 (CryptoCell Expanded128)

-- | CPortableerence Implementation for AES192 in ECB Mode
data CPortable192 (s :: Stage) = CPortable192 (CryptoCell Expanded192)

-- | CPortableerence Implementation for AES256 in ECB Mode
data CPortable256 (s :: Stage) = CPortable256 (CryptoCell Expanded256)
