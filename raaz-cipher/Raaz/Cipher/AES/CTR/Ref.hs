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
  type MemoryOf (HGadget (AESOp CTR KEY128 EncryptMode))    = (AESKEYMem Expanded128, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = applyGad g encrypt128

instance Gadget (HGadget (AESOp CTR KEY192 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CTR KEY192 EncryptMode)) = AES CTR KEY192
  type MemoryOf (HGadget (AESOp CTR KEY192 EncryptMode))    = (AESKEYMem Expanded192, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = applyGad g encrypt192

instance Gadget (HGadget (AESOp CTR KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (AESOp CTR KEY256 EncryptMode)) = AES CTR KEY256
  type MemoryOf (HGadget (AESOp CTR KEY256 EncryptMode))    = (AESKEYMem Expanded256, AESIVMem)
  newGadgetWithMemory                                       = return . HGadget
  getMemory (HGadget m)                                     = m
  apply g                                                   = applyGad g encrypt256

applyGad g@(HGadget (AESKEYMem ex,AESIVMem s)) with n cptr = do
    expanded <- cellPeek ex
    initial <- withCell s load
    (newiv,restptr) <- foldM (moveAndHash expanded) (initial,cptr) [1..nblks]
    final <- restOfblock expanded newiv restptr
    withCell s (flip store final)
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

{-# ANN module "HLint: ignore Use section" #-}
