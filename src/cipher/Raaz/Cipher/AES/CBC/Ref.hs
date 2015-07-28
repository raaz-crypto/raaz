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

import Raaz.Cipher.AES.CBC.Type()
import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal

------------------------  Gadgets alias ----------------

-- The encryption gadget
type EncryptG key = HAESGadget CBC key EncryptMode

-- The decryption gadget type
type DecryptG key = HAESGadget CBC key DecryptMode

----------------------- KEY128 CBC ----------------------


instance Gadget (EncryptG KEY128) where
  type PrimitiveOf (EncryptG KEY128) = AES CBC KEY128
  apply g = loadAndApply moveAndEncrypt g encrypt128

instance Gadget (DecryptG KEY128) where
  type PrimitiveOf (DecryptG KEY128) = AES CBC KEY128
  apply g = loadAndApply moveAndDecrypt g decrypt128

instance Gadget (EncryptG KEY192) where
  type PrimitiveOf (EncryptG KEY192) = AES CBC KEY192
  apply g = loadAndApply moveAndEncrypt g encrypt192

instance Gadget (DecryptG KEY192) where
  type PrimitiveOf (DecryptG KEY192) = AES CBC KEY192
  apply g = loadAndApply moveAndDecrypt g decrypt192

instance Gadget (EncryptG KEY256) where
  type PrimitiveOf (EncryptG KEY256) = AES CBC KEY256
  apply g = loadAndApply moveAndEncrypt g encrypt256

instance Gadget (DecryptG KEY256) where
  type PrimitiveOf (DecryptG KEY256) = AES CBC KEY256
  apply g = loadAndApply moveAndDecrypt g decrypt256

loadAndApply moveAndApply g@(HAESGadget kC stC) with n cptr = do
    expanded <- cellPeek kC
    initial <- withCell stC load
    final <- fst <$> foldM (const . moveAndApply expanded sz with) (initial,cptr) [1..n]
    withCell stC (flip store final)
    where
      sz = blockSize (getPrim g)

-- This function trans

getPrim :: Gadget g => g -> PrimitiveOf g
getPrim _ = undefined



moveAndEncrypt :: Expanded key
               -> BYTES Int
               -> (STATE -> Expanded key -> STATE)
               -> (STATE, CryptoPtr)
               -> IO (STATE, CryptoPtr)
moveAndEncrypt expanded sz with (cxt,ptr) = do
  blk <- load ptr
  let newCxt = with (blk `xorState` cxt) expanded
  store ptr newCxt
  return (newCxt, ptr `movePtr` sz)


moveAndDecrypt :: Expanded key
               -> BYTES Int
               -> (STATE -> Expanded key -> STATE)
               -> (STATE,CryptoPtr)
               -> IO (STATE,CryptoPtr)
moveAndDecrypt expanded sz with (cxt,ptr) = do
  blk <- load ptr
  let newCxt = with blk expanded
  store ptr (newCxt `xorState` cxt)
  return (blk, ptr `movePtr` sz)


{-# ANN module "HLint: ignore Use section" #-}
