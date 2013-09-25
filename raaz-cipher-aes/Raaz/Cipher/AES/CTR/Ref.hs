{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Ref (Ref128, Ref256) where

import Control.Monad
import Data.Bits                 (xor)
import Data.Word                 (Word8)
import Foreign.Ptr
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.CTR.Type
import Raaz.Cipher.AES.Ref.Type
import Raaz.Cipher.AES.Ref.Block
import Raaz.Cipher.AES.Type

--------------------- AES128 ---------------------------------------------------

instance Gadget (Ref128 Encryption) where
  type PrimitiveOf (Ref128 Encryption) = AES128 CTR Encryption
  type MemoryOf (Ref128 Encryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadget cc = return $ Ref128 cc
  initialize (Ref128 (ek,s)) (AES128EIV (k,iv)) = do
    cellStore ek (expand128 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES128
  apply g@(Ref128 mem) n cptr = applyGad g mem encrypt128 n cptr

instance Gadget (Ref128 Decryption) where
  type PrimitiveOf (Ref128 Decryption) = AES128 CTR Decryption
  type MemoryOf (Ref128 Decryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadget cc = return $ Ref128 cc
  initialize (Ref128 (ek,s)) (AES128DIV (k,iv)) = do
    cellStore ek (expand128 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES128
  apply g@(Ref128 mem) n cptr = applyGad g mem encrypt128 n cptr


--------------------- AES192 ---------------------------------------------------

instance Gadget (Ref192 Encryption) where
  type PrimitiveOf (Ref192 Encryption) = AES192 CTR Encryption
  type MemoryOf (Ref192 Encryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadget cc = return $ Ref192 cc
  initialize (Ref192 (ek,s)) (AES192EIV (k,iv)) = do
    cellStore ek (expand192 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES192
  apply g@(Ref192 mem) n cptr = applyGad g mem encrypt192 n cptr

instance Gadget (Ref192 Decryption) where
  type PrimitiveOf (Ref192 Decryption) = AES192 CTR Decryption
  type MemoryOf (Ref192 Decryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadget cc = return $ Ref192 cc
  initialize (Ref192 (ek,s)) (AES192DIV (k,iv)) =  do
    cellStore ek (expand192 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES192
  apply g@(Ref192 mem) n cptr = applyGad g mem encrypt192 n cptr


--------------------- AES256 ---------------------------------------------------

instance Gadget (Ref256 Encryption) where
  type PrimitiveOf (Ref256 Encryption) = AES256 CTR Encryption
  type MemoryOf (Ref256 Encryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadget cc = return $ Ref256 cc
  initialize (Ref256 (ek,s)) (AES256EIV (k,iv)) = do
    cellStore ek (expand256 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES256
  apply g@(Ref256 mem) n cptr = applyGad g mem encrypt256 n cptr

instance Gadget (Ref256 Decryption) where
  type PrimitiveOf (Ref256 Decryption) = AES256 CTR Decryption
  type MemoryOf (Ref256 Decryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadget cc = return $ Ref256 cc
  initialize (Ref256 (ek,s)) (AES256DIV (k,iv)) = do
    cellStore ek (expand256 $ fromByteString k)
    cellStore s $ fromByteString iv
  finalize _ = return AES256
  apply g@(Ref256 mem) n cptr = applyGad g mem encrypt256 n cptr


applyGad :: (Gadget g, Storable k) => g
                                -> (CryptoCell k,CryptoCell STATE)
                                -> (STATE -> k -> STATE)
                                -> BLOCKS (PrimitiveOf g)
                                -> CryptoPtr
                                -> IO ()
applyGad g (ex,s) with n cptr = do
    expanded <- cellLoad ex
    initial <- cellLoad s
    (newiv,restptr) <- foldM (moveAndHash expanded) (initial,cptr) [1..nblks]
    final <- restOfblock expanded newiv restptr
    cellStore s final
    where
      nblks = (fromIntegral n) `div` (fromIntegral realsz) :: Int
      nextra = (fromIntegral n) `rem` (fromIntegral realsz) :: Int

      moveAndHash expanded (cxt,ptr) _ = do
        blk <- peek (castPtr ptr)
        let newCxt = with cxt expanded
        poke (castPtr ptr) (newCxt `xorState` blk)
        return (incrState cxt, ptr `movePtr` blocksz)

      restOfblock expanded cxt cptr' | nextra <= 0 = return cxt
                                     | otherwise = do
        let newCxt = with cxt expanded
        xorWords cptr' nextra (stateToList newCxt)
        return $ incrState cxt

      xorWords :: CryptoPtr -> Int -> [Word8] -> IO ()
      xorWords _ 0 _  = return ()
      xorWords _ _ [] = return ()
      xorWords ptr left (w:ws) = do
        x <- peek (castPtr ptr)
        poke (castPtr ptr) (x `xor` w)
        xorWords (ptr `movePtr` wsize) (left-1) ws
      wsize = BYTES $ sizeOf (undefined :: Word8)
      getPrim :: Gadget g => g -> PrimitiveOf g
      getPrim _ = undefined
      sz = blockSize (getPrim g)
      blocksz = BYTES 16
      realsz = blocksz `div` sz
