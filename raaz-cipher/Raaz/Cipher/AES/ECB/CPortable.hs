{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import Foreign.Storable         (sizeOf)
import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr            (allocaBuffer)

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Ref.Type
import Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: CryptoPtr  -- ^ expanded key
            -> CryptoPtr  -- ^ key
            -> Int        -- ^ key type => 0 - 128, 1 - 192, 2 - 256
            -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESECBEncrypt"
  c_ecb_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESECBDecrypt"
  c_ecb_decrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

--------------------- AES128 ---------------------------------------------------

instance Gadget (CPortable128 ECB Encryption) where
  type PrimitiveOf (CPortable128 ECB Encryption) = AES128 ECB Encryption
  type MemoryOf (CPortable128 ECB Encryption) = CryptoCell Expanded128
  newGadgetWithMemory cc = return $ CPortable128 cc
  initialize (CPortable128 ek) (AES128EIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 0
  finalize _ = return AES128
  apply (CPortable128 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 0

instance Gadget (CPortable128 ECB Decryption) where
  type PrimitiveOf (CPortable128 ECB Decryption) = AES128 ECB Decryption
  type MemoryOf (CPortable128 ECB Decryption) = CryptoCell Expanded128
  newGadgetWithMemory cc = return $ CPortable128 cc
  initialize (CPortable128 ek) (AES128DIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 0
  finalize _ = return AES128
  apply (CPortable128 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 0


--------------------- AES192 ---------------------------------------------------

instance Gadget (CPortable192 ECB Encryption) where
  type PrimitiveOf (CPortable192 ECB Encryption) = AES192 ECB Encryption
  type MemoryOf (CPortable192 ECB Encryption) = CryptoCell Expanded192
  newGadgetWithMemory cc = return $ CPortable192 cc
  initialize (CPortable192 ek) (AES192EIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 1
  finalize _ = return AES192
  apply (CPortable192 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 1

instance Gadget (CPortable192 ECB Decryption) where
  type PrimitiveOf (CPortable192 ECB Decryption) = AES192 ECB Decryption
  type MemoryOf (CPortable192 ECB Decryption) = CryptoCell Expanded192
  newGadgetWithMemory cc = return $ CPortable192 cc
  initialize (CPortable192 ek) (AES192DIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 1
  finalize _ = return AES192
  apply (CPortable192 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 1


--------------------- AES256 ---------------------------------------------------

instance Gadget (CPortable256 ECB Encryption) where
  type PrimitiveOf (CPortable256 ECB Encryption) = AES256 ECB Encryption
  type MemoryOf (CPortable256 ECB Encryption) = CryptoCell Expanded256
  newGadgetWithMemory cc = return $ CPortable256 cc
  initialize (CPortable256 ek) (AES256EIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 2
  finalize _ = return AES256
  apply (CPortable256 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 2

instance Gadget (CPortable256 ECB Decryption) where
  type PrimitiveOf (CPortable256 ECB Decryption) = AES256 ECB Decryption
  type MemoryOf (CPortable256 ECB Decryption) = CryptoCell Expanded256
  newGadgetWithMemory cc = return $ CPortable256 cc
  initialize (CPortable256 ek) (AES256DIV bs) = initialWith ek bs expand
   where
     expand kcptr ekcptr = c_expand ekcptr kcptr 2
  finalize _ = return AES256
  apply (CPortable256 ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 2


initialWith :: EndianStore k
            => CryptoCell ek
            -> k
            -> (CryptoPtr -> CryptoPtr -> IO ())
            -> IO ()
initialWith ek k with = allocaBuffer szk $ \kptr -> do
  store kptr k
  withCell ek $ with kptr
  where
    szk :: BYTES Int
    szk = BYTES $ sizeOf k
{-# INLINE initialWith #-}
