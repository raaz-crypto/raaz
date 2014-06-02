{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE TypeFamilies              #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import Control.Applicative
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

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

instance Gadget (CGadget (AESOp ECB KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY128 EncryptMode)) = AES ECB KEY128
  type MemoryOf (CGadget (AESOp ECB KEY128 EncryptMode)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand128 k ek
  finalize (CGadget ek) = do
    key <- cCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 0

instance Gadget (CGadget (AESOp ECB KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY128 DecryptMode)) = AES ECB KEY128
  type MemoryOf (CGadget (AESOp ECB KEY128 DecryptMode)) = CryptoCell Expanded128
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand128 k ek
  finalize (CGadget ek) = do
    key <- cCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_decrypt 0

instance Gadget (CGadget (AESOp ECB KEY192 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY192 EncryptMode)) = AES ECB KEY192
  type MemoryOf (CGadget (AESOp ECB KEY192 EncryptMode)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand192 k ek
  finalize (CGadget ek) = do
    key <- cCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 1

instance Gadget (CGadget (AESOp ECB KEY192 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY192 DecryptMode)) = AES ECB KEY192
  type MemoryOf (CGadget (AESOp ECB KEY192 DecryptMode)) = CryptoCell Expanded192
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand192 k ek
  finalize (CGadget ek) = do
    key <- cCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_decrypt 1

instance Gadget (CGadget (AESOp ECB KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY256 EncryptMode)) = AES ECB KEY256
  type MemoryOf (CGadget (AESOp ECB KEY256 EncryptMode)) = CryptoCell Expanded256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget ek) (AESCxt k) = cExpand256 k ek
  finalize (CGadget ek) = do
    key <- cCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply = loadAndApply c_ecb_encrypt 2

instance Gadget (CGadget (AESOp ECB KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp ECB KEY256 DecryptMode)) = AES ECB KEY256
  type MemoryOf (CGadget (AESOp ECB KEY256 DecryptMode)) = CryptoCell Expanded256
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
