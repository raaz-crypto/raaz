{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE TypeFamilies              #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.CBC.CPortable () where

import Control.Applicative
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Cipher.AES.CBC.Type
import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESCBCEncrypt"
  c_cbc_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESCBCDecrypt"
  c_cbc_decrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

instance Gadget (CGadget (AESOp CBC KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY128 EncryptMode)) = AES CBC KEY128
  type MemoryOf (CGadget (AESOp CBC KEY128 EncryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand128 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress128 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply c_cbc_encrypt 0

instance Gadget (CGadget (AESOp CBC KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY128 DecryptMode)) = AES CBC KEY128
  type MemoryOf (CGadget (AESOp CBC KEY128 DecryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand128 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress128 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply c_cbc_decrypt 0

instance Gadget (CGadget (AESOp CBC KEY192 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY192 EncryptMode)) = AES CBC KEY192
  type MemoryOf (CGadget (AESOp CBC KEY192 EncryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand192 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress192 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key,state)
  apply = loadAndApply c_cbc_encrypt 1

instance Gadget (CGadget (AESOp CBC KEY192 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY192 DecryptMode)) = AES CBC KEY192
  type MemoryOf (CGadget (AESOp CBC KEY192 DecryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand192 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress192 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key,state)
  apply = loadAndApply c_cbc_decrypt 1

instance Gadget (CGadget (AESOp CBC KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY256 EncryptMode)) = AES CBC KEY256
  type MemoryOf (CGadget (AESOp CBC KEY256 EncryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand256 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress256 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key,state)
  apply = loadAndApply c_cbc_encrypt 2

instance Gadget (CGadget (AESOp CBC KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY256 DecryptMode)) = AES CBC KEY256
  type MemoryOf (CGadget (AESOp CBC KEY256 DecryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand256 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress256 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key,state)
  apply = loadAndApply c_cbc_decrypt 2

loadAndApply encrypt i (CGadget (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
