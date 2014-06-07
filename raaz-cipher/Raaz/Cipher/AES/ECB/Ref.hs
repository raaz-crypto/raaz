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
  type MemoryOf (HGadget (AESOp ECB KEY128 EncryptMode)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand128 k ek
  finalize (HGadget ek) = do
    key <- hCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt128

instance Gadget (HGadget (AESOp ECB KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY128 DecryptMode)) = AES ECB KEY128
  type MemoryOf (HGadget (AESOp ECB KEY128 DecryptMode)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand128 k ek
  finalize (HGadget ek) = do
    key <- hCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g decrypt128

instance Gadget (HGadget (AESOp ECB KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY192 EncryptMode)) = AES ECB KEY192
  type MemoryOf (HGadget (AESOp ECB KEY192 EncryptMode)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand192 k ek
  finalize (HGadget ek) = do
    key <- hCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt192

instance Gadget (HGadget (AESOp ECB KEY192 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY192 DecryptMode)) = AES ECB KEY192
  type MemoryOf (HGadget (AESOp ECB KEY192 DecryptMode)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand192 k ek
  finalize (HGadget ek) = do
    key <- hCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g decrypt192

instance Gadget (HGadget (AESOp ECB KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY256 EncryptMode)) = AES ECB KEY256
  type MemoryOf (HGadget (AESOp ECB KEY256 EncryptMode)) = CryptoCell Expanded256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand256 k ek
  finalize (HGadget ek) = do
    key <- hCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt256

instance Gadget (HGadget (AESOp ECB KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (AESOp ECB KEY256 DecryptMode)) = AES ECB KEY256
  type MemoryOf (HGadget (AESOp ECB KEY256 DecryptMode)) = CryptoCell Expanded256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand256 k ek
  finalize (HGadget ek) = do
    key <- hCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g decrypt256


loadAndApply moveAndApply g@(HGadget ex) with n cptr = do
    expanded <- cellLoad ex
    void $ foldM (const . moveAndApply expanded sz with) cptr [1..n]
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
