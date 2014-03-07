{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.CTR.CPortable () where

import           Control.Applicative
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types

import           Raaz.Cipher.AES.Block.Type
import           Raaz.Cipher.AES.Block.Internal
import           Raaz.Cipher.AES.CTR.Type
import           Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESCTREncrypt"
  c_ctr_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key Type
                 -> IO ()

instance Gadget (CGadget (Cipher AES KEY128 CTR Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY128 CTR Encryption)) = Cipher AES KEY128 CTR Encryption
  type MemoryOf (CGadget (Cipher AES KEY128 CTR Encryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand128 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress128 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 0

instance Gadget (CGadget (Cipher AES KEY128 CTR Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY128 CTR Decryption)) = Cipher AES KEY128 CTR Decryption
  type MemoryOf (CGadget (Cipher AES KEY128 CTR Decryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand128 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress128 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 0

instance Gadget (CGadget (Cipher AES KEY192 CTR Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY192 CTR Encryption)) = Cipher AES KEY192 CTR Encryption
  type MemoryOf (CGadget (Cipher AES KEY192 CTR Encryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand192 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress192 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 1

instance Gadget (CGadget (Cipher AES KEY192 CTR Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY192 CTR Decryption)) = Cipher AES KEY192 CTR Decryption
  type MemoryOf (CGadget (Cipher AES KEY192 CTR Decryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand192 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress192 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 1

instance Gadget (CGadget (Cipher AES KEY256 CTR Encryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY256 CTR Encryption)) = Cipher AES KEY256 CTR Encryption
  type MemoryOf (CGadget (Cipher AES KEY256 CTR Encryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand256 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress256 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 2

instance Gadget (CGadget (Cipher AES KEY256 CTR Decryption)) where
  type PrimitiveOf (CGadget (Cipher AES KEY256 CTR Decryption)) = Cipher AES KEY256 CTR Decryption
  type MemoryOf (CGadget (Cipher AES KEY256 CTR Decryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand256 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress256 <$> cellLoad ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 2

loadAndApply i (CGadget (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
