{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-# LANGUAGE FlexibleContexts #-}

module Raaz.Cipher.AES.ECB.Ref () where

import Control.Applicative
import Control.Monad
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Internal

instance Gadget (HGadget (Cipher AES KEY128 ECB Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 ECB Encryption)) = Cipher AES KEY128 ECB Encryption
  type MemoryOf (HGadget (Cipher AES KEY128 ECB Encryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand128 k ek
  finalize _ = return Cipher
  apply g = loadAndApply moveAndApply g encrypt128

instance Gadget (HGadget (Cipher AES KEY128 ECB Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY128 ECB Decryption)) = Cipher AES KEY128 ECB Decryption
  type MemoryOf (HGadget (Cipher AES KEY128 ECB Decryption)) = CryptoCell Expanded128
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand128 k ek
  finalize _ = return Cipher
  apply g = loadAndApply moveAndApply g decrypt128

instance Gadget (HGadget (Cipher AES KEY192 ECB Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 ECB Encryption)) = Cipher AES KEY192 ECB Encryption
  type MemoryOf (HGadget (Cipher AES KEY192 ECB Encryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand192 k ek
  finalize _ = return Cipher
  apply g = loadAndApply moveAndApply g encrypt192

instance Gadget (HGadget (Cipher AES KEY192 ECB Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY192 ECB Decryption)) = Cipher AES KEY192 ECB Decryption
  type MemoryOf (HGadget (Cipher AES KEY192 ECB Decryption)) = CryptoCell Expanded192
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand192 k ek
  finalize _ = return Cipher
  apply g = loadAndApply moveAndApply g decrypt192

instance Gadget (HGadget (Cipher AES KEY256 ECB Encryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 ECB Encryption)) = Cipher AES KEY256 ECB Encryption
  type MemoryOf (HGadget (Cipher AES KEY256 ECB Encryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand256 k ek
  finalize _ = return Cipher
  apply g = loadAndApply moveAndApply g encrypt256

instance Gadget (HGadget (Cipher AES KEY256 ECB Decryption)) where
  type PrimitiveOf (HGadget (Cipher AES KEY256 ECB Decryption)) = Cipher AES KEY256 ECB Decryption
  type MemoryOf (HGadget (Cipher AES KEY256 ECB Decryption)) = CryptoCell Expanded256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget ek) (AESIV k) = hExpand256 k ek
  finalize _ = return Cipher
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
