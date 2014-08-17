{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE TypeFamilies              #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.CBC.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Cipher.AES.CBC.Type       ()
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
  type MemoryOf (CGadget (AESOp CBC KEY128 EncryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_encrypt 0

instance Gadget (CGadget (AESOp CBC KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY128 DecryptMode)) = AES CBC KEY128
  type MemoryOf (CGadget (AESOp CBC KEY128 DecryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_decrypt 0

instance Gadget (CGadget (AESOp CBC KEY192 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY192 EncryptMode)) = AES CBC KEY192
  type MemoryOf (CGadget (AESOp CBC KEY192 EncryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_encrypt 1

instance Gadget (CGadget (AESOp CBC KEY192 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY192 DecryptMode)) = AES CBC KEY192
  type MemoryOf (CGadget (AESOp CBC KEY192 DecryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_decrypt 1

instance Gadget (CGadget (AESOp CBC KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY256 EncryptMode)) = AES CBC KEY256
  type MemoryOf (CGadget (AESOp CBC KEY256 EncryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_encrypt 2

instance Gadget (CGadget (AESOp CBC KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (AESOp CBC KEY256 DecryptMode)) = AES CBC KEY256
  type MemoryOf (CGadget (AESOp CBC KEY256 DecryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply c_cbc_decrypt 2

loadAndApply encrypt i (CGadget (AESKEYMem ek,AESIVMem civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
