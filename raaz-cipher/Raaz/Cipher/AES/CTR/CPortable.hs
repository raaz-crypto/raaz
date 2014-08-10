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
  type MemoryOf (CGadget (AESOp CTR KEY128 EncryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply 0

instance Gadget (CGadget (AESOp CTR KEY192 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CTR KEY192 EncryptMode)) = AES CTR KEY192
  type MemoryOf (CGadget (AESOp CTR KEY192 EncryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply 1

instance Gadget (CGadget (AESOp CTR KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (AESOp CTR KEY256 EncryptMode)) = AES CTR KEY256
  type MemoryOf (CGadget (AESOp CTR KEY256 EncryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . CGadget
  getMemory (CGadget m)                                     = m
  apply                                                     = loadAndApply 2

loadAndApply i (CGadget (AESKEYMem ek,AESIVMem civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
