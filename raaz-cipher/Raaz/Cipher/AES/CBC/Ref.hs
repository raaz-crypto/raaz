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
  type MemoryOf (HGadget (AESOp CBC KEY128 EncryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand128 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress128 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt128

instance Gadget (HGadget (AESOp CBC KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY128 DecryptMode)) = AES CBC KEY128
  type MemoryOf (HGadget (AESOp CBC KEY128 DecryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand128 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress128 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt128

instance Gadget (HGadget (AESOp CBC KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY192 EncryptMode)) = AES CBC KEY192
  type MemoryOf (HGadget (AESOp CBC KEY192 EncryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand192 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress192 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt192

instance Gadget (HGadget (AESOp CBC KEY192 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY192 DecryptMode)) = AES CBC KEY192
  type MemoryOf (HGadget (AESOp CBC KEY192 DecryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand192 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress192 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt192

instance Gadget (HGadget (AESOp CBC KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY256 EncryptMode)) = AES CBC KEY256
  type MemoryOf (HGadget (AESOp CBC KEY256 EncryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand256 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress256 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt256

instance Gadget (HGadget (AESOp CBC KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp CBC KEY256 DecryptMode)) = AES CBC KEY256
  type MemoryOf (HGadget (AESOp CBC KEY256 DecryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand256 k ek
    cellPoke s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress256 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt256


loadAndApply moveAndApply g@(HGadget (ex,s)) with n cptr = do
    expanded <- cellPeek ex
    initial <- cellPeek s
    final <- fst <$> foldM (const . moveAndApply expanded sz with) (initial,cptr) [1..n]
    cellPoke s final
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
