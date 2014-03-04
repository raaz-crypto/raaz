{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE TypeFamilies              #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import Foreign.Storable         (sizeOf)
import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr            (allocaBuffer)

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Internal

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

instance Gadget (CGadget (Cipher AES KEY128 ECB Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY128 ECB Encryption)) = Cipher AES KEY128 ECB Encryption
  type MemoryOf (CGadget (Cipher AES KEY128 ECB Encryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand128 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_encrypt 0

instance Gadget (CGadget (Cipher AES KEY128 ECB Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY128 ECB Decryption)) = Cipher AES KEY128 ECB Decryption
  type MemoryOf (CGadget (Cipher AES KEY128 ECB Decryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand128 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_decrypt 0

instance Gadget (CGadget (Cipher AES KEY192 ECB Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY192 ECB Encryption)) = Cipher AES KEY192 ECB Encryption
  type MemoryOf (CGadget (Cipher AES KEY192 ECB Encryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand192 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_encrypt 1

instance Gadget (CGadget (Cipher AES KEY192 ECB Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY192 ECB Decryption)) = Cipher AES KEY192 ECB Decryption
  type MemoryOf (CGadget (Cipher AES KEY192 ECB Decryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand192 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_decrypt 1

instance Gadget (CGadget (Cipher AES KEY256 ECB Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY256 ECB Encryption)) = Cipher AES KEY256 ECB Encryption
  type MemoryOf (CGadget (Cipher AES KEY256 ECB Encryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand256 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_encrypt 2

instance Gadget (CGadget (Cipher AES KEY256 ECB Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY256 ECB Decryption)) = Cipher AES KEY256 ECB Decryption
  type MemoryOf (CGadget (Cipher AES KEY256 ECB Decryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESIV k) = cExpand256 k ek
  finalize _ = return Cipher
  apply = loadAndApply c_ecb_decrypt 2

loadAndApply encrypt i (CGadget ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = encrypt ekptr cptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
