{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.CTR.CPortable () where

import           Control.Applicative
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types

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

instance Gadget (CGadget (AESOp CTR KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CTR KEY128 EncryptMode)) = AES CTR KEY128
  type MemoryOf (CGadget (AESOp CTR KEY128 EncryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand128 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress128 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 0

instance Gadget (CGadget (AESOp CTR KEY192 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CTR KEY192 EncryptMode)) = AES CTR KEY192
  type MemoryOf (CGadget (AESOp CTR KEY192 EncryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand192 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress192 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 1

instance Gadget (CGadget (AESOp CTR KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CTR KEY256 EncryptMode)) = AES CTR KEY256
  type MemoryOf (CGadget (AESOp CTR KEY256 EncryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . CGadget
  initialize (CGadget (ek,s)) (AESCxt (k,iv)) = do
    withCell s (flip store iv)
    cExpand256 k ek
  finalize (CGadget (ek,s)) = do
    key <- cCompress256 <$> cellPeek ek
    state <- withCell s load
    return $ AESCxt (key, state)
  apply = loadAndApply 2

loadAndApply i (CGadget (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
