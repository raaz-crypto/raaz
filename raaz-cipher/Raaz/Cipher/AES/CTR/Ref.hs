{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Ref () where

import Control.Applicative
import Control.Monad
import Data.Bits           ( xor    )
import Data.ByteString     ( unpack )
import Data.Word           ( Word8  )
import Foreign.Ptr
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.AES.CTR.Type
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Gadget (HGadget (AESOp CTR KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CTR KEY128 EncryptMode)) = AES CTR KEY128
  type MemoryOf (HGadget (AESOp CTR KEY128 EncryptMode)) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand128 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress128 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = applyGad g encrypt128

instance Gadget (HGadget (AESOp CTR KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CTR KEY192 EncryptMode)) = AES CTR KEY192
  type MemoryOf (HGadget (AESOp CTR KEY192 EncryptMode)) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand192 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress192 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = applyGad g encrypt192

instance Gadget (HGadget (AESOp CTR KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CTR KEY256 EncryptMode)) = AES CTR KEY256
  type MemoryOf (HGadget (AESOp CTR KEY256 EncryptMode)) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (ek,s)) (AESCxt (k,iv)) = do
    hExpand256 k ek
    cellStore s iv
  finalize (HGadget (ek,s)) = do
    key <- hCompress256 <$> cellPeek ek
    state <- cellPeek s
    return $ AESCxt (key,state)
  apply g = applyGad g encrypt256

applyGad g@(HGadget (ex,s)) with n cptr = do
    expanded <- cellPeek ex
    initial <- cellPeek s
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
