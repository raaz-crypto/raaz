{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE TypeFamilies              #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import Control.Applicative
import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types

import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.AES.Block.Internal
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

instance Gadget (CGadget (Cipher (AES ECB) KEY128 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY128 Encryption)) = Cipher (AES ECB) KEY128 Encryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY128 Encryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand128 k ek
  finalize (CGadget ek) = do
    key <- cCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 0

instance Gadget (CGadget (Cipher (AES ECB) KEY128 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY128 Decryption)) = Cipher (AES ECB) KEY128 Decryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY128 Decryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand128 k ek
  finalize (CGadget ek) = do
    key <- cCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_decrypt 0

instance Gadget (CGadget (Cipher (AES ECB) KEY192 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY192 Encryption)) = Cipher (AES ECB) KEY192 Encryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY192 Encryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand192 k ek
  finalize (CGadget ek) = do
    key <- cCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 1

instance Gadget (CGadget (Cipher (AES ECB) KEY192 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY192 Decryption)) = Cipher (AES ECB) KEY192 Decryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY192 Decryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand192 k ek
  finalize (CGadget ek) = do
    key <- cCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_decrypt 1

instance Gadget (CGadget (Cipher (AES ECB) KEY256 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY256 Encryption)) = Cipher (AES ECB) KEY256 Encryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY256 Encryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand256 k ek
  finalize (CGadget ek) = do
    key <- cCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 2

instance Gadget (CGadget (Cipher (AES ECB) KEY256 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (AES ECB) KEY256 Decryption)) = Cipher (AES ECB) KEY256 Decryption
  type MemoryOf (CGadget (Cipher (AES ECB) KEY256 Decryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand256 k ek
  finalize (CGadget ek) = do
    key <- cCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_decrypt 2

loadAndApply encrypt i (CGadget ek) n cptr = withCell ek doStuff
    where
      doStuff ekptr = encrypt ekptr cptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
