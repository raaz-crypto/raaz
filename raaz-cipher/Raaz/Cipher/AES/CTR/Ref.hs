{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Ref () where

import Control.Monad
import Data.Bits                    (xor)
import Data.ByteString              (unpack)
import Data.Word                    (Word8)
import Foreign.Ptr
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.CTR.Type
import Raaz.Cipher.AES.Internal


instance Gadget (HGadget (Cipher AES KEY128 CTR Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 CTR Encryption)) = Cipher AES KEY128 CTR Encryption
  type MemoryOf (HGadget (Cipher AES KEY128 CTR Encryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand128 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt128

instance Gadget (HGadget (Cipher AES KEY128 CTR Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 CTR Decryption)) = Cipher AES KEY128 CTR Decryption
  type MemoryOf (HGadget (Cipher AES KEY128 CTR Decryption)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand128 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt128

instance Gadget (HGadget (Cipher AES KEY192 CTR Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 CTR Encryption)) = Cipher AES KEY192 CTR Encryption
  type MemoryOf (HGadget (Cipher AES KEY192 CTR Encryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand192 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt192

instance Gadget (HGadget (Cipher AES KEY192 CTR Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 CTR Decryption)) = Cipher AES KEY192 CTR Decryption
  type MemoryOf (HGadget (Cipher AES KEY192 CTR Decryption)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand192 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt192

instance Gadget (HGadget (Cipher AES KEY256 CTR Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 CTR Encryption)) = Cipher AES KEY256 CTR Encryption
  type MemoryOf (HGadget (Cipher AES KEY256 CTR Encryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand256 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt256

instance Gadget (HGadget (Cipher AES KEY256 CTR Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 CTR Decryption)) = Cipher AES KEY256 CTR Decryption
  type MemoryOf (HGadget (Cipher AES KEY256 CTR Decryption)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESIV (k,iv)) = do
    hExpand256 k ek
    cellStore s iv
  finalize _ = return Cipher
  apply g = applyGad g encrypt256

applyGad g@(HGadget (ex,s)) with n cptr = do
    expanded <- cellLoad ex
    initial <- cellLoad s
    (newiv,restptr) <- foldM (moveAndHash expanded) (initial,cptr) [1..nblks]
    final <- restOfblock expanded newiv restptr
    cellStore s final
    where
      nblks = fromIntegral n `div` fromIntegral realsz :: Int
      nextra = fromIntegral n `rem` fromIntegral realsz :: Int

      moveAndHash expanded (cxt,ptr) _ = do
        blk <- load ptr
        let newCxt = with cxt expanded
        store ptr (newCxt `xorState` blk)
        return (incrState cxt, ptr `movePtr` blocksz)

      restOfblock expanded cxt cptr' | nextra <= 0 = return cxt
                                     | otherwise = do
        let newCxt = with cxt expanded
        xorWords cptr' nextra (unpack $ toByteString newCxt)
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
