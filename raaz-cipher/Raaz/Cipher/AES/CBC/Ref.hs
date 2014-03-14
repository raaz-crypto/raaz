{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module Raaz.Cipher.AES.CBC.Ref () where

import Control.Applicative
import Control.Monad

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.CBC.Type
import Raaz.Cipher.AES.Internal


instance Gadget (HGadget (Cipher AES KEY128 CBC Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 CBC Encryption)) = Cipher AES KEY128 CBC Encryption
  type MemoryOf (HGadget (Cipher AES KEY128 CBC Encryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand128 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress128 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt128

instance Gadget (HGadget (Cipher AES KEY128 CBC Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 CBC Decryption)) = Cipher AES KEY128 CBC Decryption
  type MemoryOf (HGadget (Cipher AES KEY128 CBC Decryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand128 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress128 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt128

instance Gadget (HGadget (Cipher AES KEY192 CBC Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 CBC Encryption)) = Cipher AES KEY192 CBC Encryption
  type MemoryOf (HGadget (Cipher AES KEY192 CBC Encryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand192 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress192 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt192

instance Gadget (HGadget (Cipher AES KEY192 CBC Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 CBC Decryption)) = Cipher AES KEY192 CBC Decryption
  type MemoryOf (HGadget (Cipher AES KEY192 CBC Decryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand192 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress192 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt192

instance Gadget (HGadget (Cipher AES KEY256 CBC Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 CBC Encryption)) = Cipher AES KEY256 CBC Encryption
  type MemoryOf (HGadget (Cipher AES KEY256 CBC Encryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand256 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress256 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndEncrypt g encrypt256

instance Gadget (HGadget (Cipher AES KEY256 CBC Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 CBC Decryption)) = Cipher AES KEY256 CBC Decryption
  type MemoryOf (HGadget (Cipher AES KEY256 CBC Decryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand256 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress256 <$> cellLoad ek
    state <- cellLoad s
    return $ AESCxt (key,state)
  apply g = loadAndApply moveAndDecrypt g decrypt256


loadAndApply moveAndApply g@(HGadget (ex,s)) with n cptr = do
    expanded <- cellLoad ex
    initial <- cellLoad s
    final <- fst <$> foldM (const . moveAndApply expanded sz with) (initial,cptr) [1..n]
    cellStore s final
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
