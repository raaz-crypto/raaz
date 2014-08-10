{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module Raaz.Cipher.AES.CBC.Ref () where

import Control.Applicative
import Control.Monad

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.AES.CBC.Type
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Gadget (HGadget (AESOp CBC KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY128 EncryptMode)) = AES CBC KEY128
  type MemoryOf (HGadget (AESOp CBC KEY128 EncryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndEncrypt g encrypt128

instance Gadget (HGadget (AESOp CBC KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY128 DecryptMode)) = AES CBC KEY128
  type MemoryOf (HGadget (AESOp CBC KEY128 DecryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndDecrypt g decrypt128

instance Gadget (HGadget (AESOp CBC KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY192 EncryptMode)) = AES CBC KEY192
  type MemoryOf (HGadget (AESOp CBC KEY192 EncryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndEncrypt g encrypt192

instance Gadget (HGadget (AESOp CBC KEY192 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY192 DecryptMode)) = AES CBC KEY192
  type MemoryOf (HGadget (AESOp CBC KEY192 DecryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndDecrypt g decrypt192

instance Gadget (HGadget (AESOp CBC KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY256 EncryptMode)) = AES CBC KEY256
  type MemoryOf (HGadget (AESOp CBC KEY256 EncryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndEncrypt g encrypt256

instance Gadget (HGadget (AESOp CBC KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY256 DecryptMode)) = AES CBC KEY256
  type MemoryOf (HGadget (AESOp CBC KEY256 DecryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g = loadAndApply moveAndDecrypt g decrypt256

loadAndApply moveAndApply g@(HGadget (AESKEYMem ex,AESIVMem s)) with n cptr = do
    expanded <- cellLoad ex
    initial <- withCell s load
    final <- fst <$> foldM (const . moveAndApply expanded sz with) (initial,cptr) [1..n]
    withCell s (flip store final)
    where
      sz = blockSize (getPrim g)

getPrim :: Gadget g => g -> PrimitiveOf g
getPrim _ = undefined

moveAndEncrypt :: ek
               -> BYTES Int
               -> (STATE -> ek -> STATE)
               -> (STATE,CryptoPtr)
               -> IO (STATE,CryptoPtr)
moveAndEncrypt expanded sz with (cxt,ptr) = do
  blk <- load ptr
  let newCxt = with (blk `xorState` cxt) expanded
  store ptr newCxt
  return (newCxt, ptr `movePtr` sz)

moveAndDecrypt :: ek
               -> BYTES Int
               -> (STATE -> ek -> STATE)
               -> (STATE,CryptoPtr)
               -> IO (STATE,CryptoPtr)
moveAndDecrypt expanded sz with (cxt,ptr) = do
  blk <- load ptr
  let newCxt = with blk expanded
  store ptr (newCxt `xorState` cxt)
  return (blk, ptr `movePtr` sz)
