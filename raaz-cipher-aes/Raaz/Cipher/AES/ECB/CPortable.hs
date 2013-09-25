{-# LANGUAGE DataKinds                #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as BS
import           Foreign.Marshal.Alloc    (allocaBytes)
import           Foreign.Storable         (sizeOf)
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString     (withByteString)

import           Raaz.Cipher.AES.ECB.Type
import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Type

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand128"
  c_expand128  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand192"
  c_expand192  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand256"
  c_expand256  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptECB128"
  c_ecb_encrypt128  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptECB192"
  c_ecb_encrypt192  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptECB256"
  c_ecb_encrypt256  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESDecryptECB128"
  c_ecb_decrypt128  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESDecryptECB192"
  c_ecb_decrypt192  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESDecryptECB256"
  c_ecb_decrypt256  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> Int        -- ^ Number of Blocks
                    -> IO ()


--------------------- AES128 ---------------------------------------------------

instance Gadget (CPortable128 Encryption) where
  type PrimitiveOf (CPortable128 Encryption) = AES128 ECB Encryption
  type MemoryOf (CPortable128 Encryption) = (CryptoCell Expanded128)
  newGadget cc = return $ CPortable128 cc
  initialize (CPortable128 ek) (AES128EIV bs) = initialWith ek bs sz c_expand128
   where
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt128 ekptr cptr (fromIntegral n)

instance Gadget (CPortable128 Decryption) where
  type PrimitiveOf (CPortable128 Decryption) = AES128 ECB Decryption
  type MemoryOf (CPortable128 Decryption) = (CryptoCell Expanded128)
  newGadget cc = return $ CPortable128 cc
  initialize (CPortable128 ek) (AES128DIV bs) = initialWith ek bs sz c_expand128
   where
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt128 ekptr cptr (fromIntegral n)


--------------------- AES192 ---------------------------------------------------

instance Gadget (CPortable192 Encryption) where
  type PrimitiveOf (CPortable192 Encryption) = AES192 ECB Encryption
  type MemoryOf (CPortable192 Encryption) = (CryptoCell Expanded192)
  newGadget cc = return $ CPortable192 cc
  initialize (CPortable192 ek) (AES192EIV bs) = initialWith ek bs sz c_expand192
   where
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt192 ekptr cptr (fromIntegral n)

instance Gadget (CPortable192 Decryption) where
  type PrimitiveOf (CPortable192 Decryption) = AES192 ECB Decryption
  type MemoryOf (CPortable192 Decryption) = (CryptoCell Expanded192)
  newGadget cc = return $ CPortable192 cc
  initialize (CPortable192 ek) (AES192DIV bs) = initialWith ek bs sz c_expand192
   where
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt192 ekptr cptr (fromIntegral n)


--------------------- AES256 ---------------------------------------------------

instance Gadget (CPortable256 Encryption) where
  type PrimitiveOf (CPortable256 Encryption) = AES256 ECB Encryption
  type MemoryOf (CPortable256 Encryption) = (CryptoCell Expanded256)
  newGadget cc = return $ CPortable256 cc
  initialize (CPortable256 ek) (AES256EIV bs) = initialWith ek bs sz c_expand256
   where
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt256 ekptr cptr (fromIntegral n)

instance Gadget (CPortable256 Decryption) where
  type PrimitiveOf (CPortable256 Decryption) = AES256 ECB Decryption
  type MemoryOf (CPortable256 Decryption) = (CryptoCell Expanded256)
  newGadget cc = return $ CPortable256 cc
  initialize (CPortable256 ek) (AES256DIV bs) = initialWith ek bs sz c_expand256
   where
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt256 ekptr cptr (fromIntegral n)


initialWith :: CryptoCell ek
            -> ByteString
            -> Int
            -> (CryptoPtr -> CryptoPtr -> IO ())
            -> IO ()
initialWith ek bs sz with | BS.length bs == sz = withCell ek (withByteString bs . with)
                         | otherwise          = error "Unable to fill key with given data"
{-# INLINE initialWith #-}
