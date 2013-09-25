{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import           Foreign.Storable
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types

import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Ref.Block ()
import           Raaz.Cipher.AES.Type


-- | Primitive for AES128 in CTR Mode
instance Primitive (AES128 CTR Encryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 CTR Encryption) = AES128EIV (ByteString, ByteString)

instance Primitive (AES128 CTR Decryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES128 CTR Decryption) = AES128DIV (ByteString, ByteString)

-- | Primitive for AES192 in CTR Mode
instance Primitive (AES192 CTR Encryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 CTR Encryption) = AES192EIV (ByteString, ByteString)

instance Primitive (AES192 CTR Decryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES192 CTR Decryption) = AES192DIV (ByteString, ByteString)

-- | Primitive for AES256 in CTR Mode
instance Primitive (AES256 CTR Encryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 CTR Encryption) = AES256EIV (ByteString, ByteString)

instance Primitive (AES256 CTR Decryption) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype IV (AES256 CTR Decryption) = AES256DIV (ByteString, ByteString)

-- | First KEY then 128bit initialization vector
getIVCTR :: (Storable k) => ByteString -> k -> (ByteString,ByteString)
getIVCTR bs k = (key,iv)
  where
      key = BS.take sizek bs
      rest = BS.drop sizek bs
      iv = BS.take sizeiv rest
      sizek = sizeOf k
      sizeiv = sizeOf (undefined :: STATE)

instance Initializable (AES128 CTR Encryption) where
  getIV src = AES128EIV $ getIVCTR src (undefined :: KEY128)

instance Initializable (AES128 CTR Decryption) where
  getIV src = AES128DIV $ getIVCTR src (undefined :: KEY128)

instance Initializable (AES192 CTR Encryption) where
  getIV src = AES192EIV $ getIVCTR src (undefined :: KEY192)

instance Initializable (AES192 CTR Decryption) where
  getIV src = AES192DIV $ getIVCTR src (undefined :: KEY192)

instance Initializable (AES256 CTR Encryption) where
  getIV src = AES256EIV $ getIVCTR src (undefined :: KEY256)

instance Initializable (AES256 CTR Decryption) where
  getIV src = AES256DIV $ getIVCTR src (undefined :: KEY256)

-- | Reference Implementation for AES128 in CTR Mode
data Ref128 (s :: Stage) = Ref128 (CryptoCell Expanded128, CryptoCell STATE)

-- | Reference Implementation for AES192 in CTR Mode
data Ref192 (s :: Stage) = Ref192 (CryptoCell Expanded192, CryptoCell STATE)

-- | Reference Implementation for AES256 in CTR Mode
data Ref256 (s :: Stage) = Ref256 (CryptoCell Expanded256, CryptoCell STATE)

-- | CPortable Implementation for AES128 in CTR Mode
data CPortable128 (s :: Stage) = CPortable128 (CryptoCell Expanded128, CryptoCell STATE)

-- | CPortable Implementation for AES192 in CTR Mode
data CPortable192 (s :: Stage) = CPortable192 (CryptoCell Expanded192, CryptoCell STATE)

-- | CPortable Implementation for AES256 in CTR Mode
data CPortable256 (s :: Stage) = CPortable256 (CryptoCell Expanded256, CryptoCell STATE)
