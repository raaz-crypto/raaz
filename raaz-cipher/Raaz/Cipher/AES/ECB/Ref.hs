{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-# LANGUAGE FlexibleContexts #-}

module Raaz.Cipher.AES.ECB.Ref () where

import Control.Applicative
import Control.Monad

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Internal

instance Gadget (HGadget (Cipher (AES ECB) KEY128 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY128 Encryption)) = Cipher (AES ECB) KEY128 Encryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY128 Encryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand128 k ek
  finalize (HGadget ek) = do
    key <- hCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt128

instance Gadget (HGadget (Cipher (AES ECB) KEY128 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY128 Decryption)) = Cipher (AES ECB) KEY128 Decryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY128 Decryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand128 k ek
  finalize (HGadget ek) = do
    key <- hCompress128 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g decrypt128

instance Gadget (HGadget (Cipher (AES ECB) KEY192 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY192 Encryption)) = Cipher (AES ECB) KEY192 Encryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY192 Encryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand192 k ek
  finalize (HGadget ek) = do
    key <- hCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt192

instance Gadget (HGadget (Cipher (AES ECB) KEY192 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY192 Decryption)) = Cipher (AES ECB) KEY192 Decryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY192 Decryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand192 k ek
  finalize (HGadget ek) = do
    key <- hCompress192 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g decrypt192

instance Gadget (HGadget (Cipher (AES ECB) KEY256 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY256 Encryption)) = Cipher (AES ECB) KEY256 Encryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY256 Encryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESCxt k) = hExpand256 k ek
  finalize (HGadget ek) = do
    key <- hCompress256 <$> cellLoad ek
    return $ AESCxt key
  apply g = loadAndApply moveAndApply g encrypt256

instance Gadget (HGadget (Cipher (AES ECB) KEY256 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (AES ECB) KEY256 Decryption)) = Cipher (AES ECB) KEY256 Decryption
  type MemoryOf (HGadget (Cipher (AES ECB) KEY256 Decryption)) = CryptoCell Expanded256
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
