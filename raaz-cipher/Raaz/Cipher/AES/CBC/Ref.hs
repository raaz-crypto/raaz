{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Ref () where

import Control.Applicative
import Control.Monad
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.CBC.Type
import Raaz.Cipher.AES.Ref.Type
import Raaz.Cipher.AES.Ref.Internal
import Raaz.Cipher.AES.Internal

--------------------- AES128 ---------------------------------------------------

instance Gadget (Ref128 CBC Encryption) where
  type PrimitiveOf (Ref128 CBC Encryption) = AES128 CBC Encryption
  type MemoryOf (Ref128 CBC Encryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref128 cc
  initialize (Ref128 (ek,s)) (AES128EIV (k,iv)) = do
    cellStore ek $ expand128 k
    cellStore s iv
  finalize _ = return AES128
  apply g@(Ref128 mem) = applyE g mem encrypt128

instance Gadget (Ref128 CBC Decryption) where
  type PrimitiveOf (Ref128 CBC Decryption) = AES128 CBC Decryption
  type MemoryOf (Ref128 CBC Decryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref128 cc
  initialize (Ref128 (ek,s)) (AES128DIV (k,iv)) = do
    cellStore ek $ expand128 k
    cellStore s iv
  finalize _ = return AES128
  apply g@(Ref128 mem) = applyD g mem decrypt128


--------------------- AES192 ---------------------------------------------------

instance Gadget (Ref192 CBC Encryption) where
  type PrimitiveOf (Ref192 CBC Encryption) = AES192 CBC Encryption
  type MemoryOf (Ref192 CBC Encryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref192 cc
  initialize (Ref192 (ek,s)) (AES192EIV (k,iv)) = do
    cellStore ek $ expand192 k
    cellStore s iv
  finalize _ = return AES192
  apply g@(Ref192 mem) = applyE g mem encrypt192

instance Gadget (Ref192 CBC Decryption) where
  type PrimitiveOf (Ref192 CBC Decryption) = AES192 CBC Decryption
  type MemoryOf (Ref192 CBC Decryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref192 cc
  initialize (Ref192 (ek,s)) (AES192DIV (k,iv)) =  do
    cellStore ek $ expand192 k
    cellStore s iv
  finalize _ = return AES192
  apply g@(Ref192 mem) = applyD g mem decrypt192


--------------------- AES256 ---------------------------------------------------

instance Gadget (Ref256 CBC Encryption) where
  type PrimitiveOf (Ref256 CBC Encryption) = AES256 CBC Encryption
  type MemoryOf (Ref256 CBC Encryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref256 cc
  initialize (Ref256 (ek,s)) (AES256EIV (k,iv)) = do
    cellStore ek $ expand256 k
    cellStore s iv
  finalize _ = return AES256
  apply g@(Ref256 mem) = applyE g mem encrypt256

instance Gadget (Ref256 CBC Decryption) where
  type PrimitiveOf (Ref256 CBC Decryption) = AES256 CBC Decryption
  type MemoryOf (Ref256 CBC Decryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory cc = return $ Ref256 cc
  initialize (Ref256 (ek,s)) (AES256DIV (k,iv)) = do
    cellStore ek $ expand256 k
    cellStore s iv
  finalize _ = return AES256
  apply g@(Ref256 mem) = applyD g mem decrypt256


loadAndApply :: (Gadget g, Storable k)
             => (k -> (STATE,CryptoPtr) -> BLOCKS (PrimitiveOf g) -> IO (STATE,CryptoPtr))
             -> g
             -> (CryptoCell k,CryptoCell STATE)
             -> BLOCKS (PrimitiveOf g)
             -> CryptoPtr
             -> IO ()
loadAndApply moveAndHash _ (ex,s) n cptr = do
    expanded <- cellLoad ex
    initial <- cellLoad s
    final <- fst <$> foldM (moveAndHash expanded) (initial,cptr) [1..n]
    cellStore s final

getPrim :: Gadget g => g -> PrimitiveOf g
getPrim _ = undefined

applyE :: (Gadget g, Storable k) => g
                                -> (CryptoCell k,CryptoCell STATE)
                                -> (STATE -> k -> STATE)
                                -> BLOCKS (PrimitiveOf g)
                                -> CryptoPtr
                                -> IO ()
applyE g tup with = loadAndApply moveAndHash g tup
    where
      sz = blockSize (getPrim g)
      moveAndHash expanded (cxt,ptr) _ = do
        blk <- load ptr
        let newCxt = with (blk `xorState` cxt) expanded
        store ptr newCxt
        return (newCxt, ptr `movePtr` sz)

applyD :: (Gadget g, Storable k) => g
                                -> (CryptoCell k,CryptoCell STATE)
                                -> (STATE -> k -> STATE)
                                -> BLOCKS (PrimitiveOf g)
                                -> CryptoPtr
                                -> IO ()
applyD g tup with = loadAndApply moveAndHash g tup
    where
      sz = blockSize (getPrim g)
      moveAndHash expanded (cxt,ptr) _ = do
        blk <- load ptr
        let newCxt = with blk expanded
        store ptr (newCxt `xorState` cxt)
        return (blk, ptr `movePtr` sz)
