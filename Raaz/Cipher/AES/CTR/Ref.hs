{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE DataKinds            #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Ref () where

import Control.Monad
import Data.Bits           ( xor    )
import Data.ByteString     ( unpack )
import Data.Word           ( Word8  )
import Foreign.Ptr
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Encode
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.AES.CTR.Type()
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


type CTRG key = HAESGadget CTR key EncryptMode

instance Gadget (CTRG KEY128) where
  type PrimitiveOf (CTRG KEY128) = AES CTR KEY128
  apply g                        = applyGad g encrypt128

instance Gadget (CTRG KEY192) where
  type PrimitiveOf (CTRG KEY192) = AES CTR KEY192
  apply g                        = applyGad g encrypt192

instance Gadget (CTRG KEY256) where
  type PrimitiveOf (CTRG KEY256) = AES CTR KEY256
  apply g                        = applyGad g encrypt256

applyGad :: ( Gadget (CTRG key), Storable (Expanded key))
         => CTRG key
         -> (STATE -> Expanded key -> STATE)
         -> BLOCKS (AES CTR key)
         -> CryptoPtr
         -> IO ()
applyGad g@(HAESGadget kC stC) with n cptr = do
    expanded <- cellPeek kC
    initial <- withCell stC load
    (newiv,restptr) <- foldM (moveAndHash expanded) (initial,cptr) [1..nblks]
    final <- restOfblock expanded newiv restptr
    withCell stC (flip store final)
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
