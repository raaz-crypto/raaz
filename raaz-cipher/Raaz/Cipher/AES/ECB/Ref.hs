{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-# LANGUAGE FlexibleContexts #-}

module Raaz.Cipher.AES.ECB.Ref () where

import Control.Applicative
import Control.Monad

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal

instance Gadget (HGadget (AESOp ECB KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY128 EncryptMode)) = AES ECB KEY128
  type MemoryOf (HGadget (AESOp ECB KEY128 EncryptMode))    = AESKEYMem Expanded128
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g encrypt128

instance Gadget (HGadget (AESOp ECB KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY128 DecryptMode)) = AES ECB KEY128
  type MemoryOf (HGadget (AESOp ECB KEY128 DecryptMode))    = AESKEYMem Expanded128
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g decrypt128

instance Gadget (HGadget (AESOp ECB KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY192 EncryptMode)) = AES ECB KEY192
  type MemoryOf (HGadget (AESOp ECB KEY192 EncryptMode))    = AESKEYMem Expanded192
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g encrypt192

instance Gadget (HGadget (AESOp ECB KEY192 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY192 DecryptMode)) = AES ECB KEY192
  type MemoryOf (HGadget (AESOp ECB KEY192 DecryptMode))    = AESKEYMem Expanded192
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g decrypt192

instance Gadget (HGadget (AESOp ECB KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY256 EncryptMode)) = AES ECB KEY256
  type MemoryOf (HGadget (AESOp ECB KEY256 EncryptMode))    = AESKEYMem Expanded256
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g encrypt256

instance Gadget (HGadget (AESOp ECB KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY256 DecryptMode)) = AES ECB KEY256
  type MemoryOf (HGadget (AESOp ECB KEY256 DecryptMode))    = AESKEYMem Expanded256
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = loadAndApply moveAndApply g decrypt256

loadAndApply process g@(HGadget (AESKEYMem ex)) with n cptr = do
    expanded <- cellPeek ex
    void $ foldM (const . process expanded sz with) cptr [1..n]
    where
      sz = blockSize (getPrim g)

getPrim :: Gadget g => g -> PrimitiveOf g
getPrim _ = undefined

moveAndApply :: ek
             -> BYTES Int
             -> (STATE -> ek -> STATE)
             -> CryptoPtr
             -> IO CryptoPtr
moveAndApply expanded sz with ptr = do
  blk <- load ptr
  let newCxt = with blk expanded
  store ptr newCxt
  return $ ptr `movePtr` sz
