{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Ref () where

import Control.Monad
import Foreign.Ptr
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Cipher.AES.ECB.Type
import Raaz.Cipher.AES.Ref.Type
import Raaz.Cipher.AES.Ref.Block
import Raaz.Cipher.AES.Type

--------------------- AES128 ---------------------------------------------------

instance Gadget (Ref128 Encryption) where
  type PrimitiveOf (Ref128 Encryption) = AES128 ECB Encryption
  type MemoryOf (Ref128 Encryption) = (CryptoCell Expanded128)
  newGadget cc = return $ Ref128 cc
  initialize (Ref128 ek) (AES128EIV k) = cellStore ek
                                         (expand128 $ fromByteString k)
  finalize _ = return AES128
  apply g@(Ref128 ex) n cptr = applyGad g ex encrypt128 n cptr

instance Gadget (Ref128 Decryption) where
  type PrimitiveOf (Ref128 Decryption) = AES128 ECB Decryption
  type MemoryOf (Ref128 Decryption) = (CryptoCell Expanded128)
  newGadget cc = return $ Ref128 cc
  initialize (Ref128 ek) (AES128DIV k) = cellStore ek
                                         (expand128 $ fromByteString k)
  finalize _ = return AES128
  apply g@(Ref128 ex) n cptr = applyGad g ex decrypt128 n cptr


--------------------- AES192 ---------------------------------------------------

instance Gadget (Ref192 Encryption) where
  type PrimitiveOf (Ref192 Encryption) = AES192 ECB Encryption
  type MemoryOf (Ref192 Encryption) = (CryptoCell Expanded192)
  newGadget cc = return $ Ref192 cc
  initialize (Ref192 ek) (AES192EIV k) = cellStore ek
                                         (expand192 $ fromByteString k)
  finalize _ = return AES192
  apply g@(Ref192 ex) n cptr = applyGad g ex encrypt192 n cptr

instance Gadget (Ref192 Decryption) where
  type PrimitiveOf (Ref192 Decryption) = AES192 ECB Decryption
  type MemoryOf (Ref192 Decryption) = (CryptoCell Expanded192)
  newGadget cc = return $ Ref192 cc
  initialize (Ref192 ek) (AES192DIV k) = cellStore ek
                                         (expand192 $ fromByteString k)
  finalize _ = return AES192
  apply g@(Ref192 ex) n cptr = applyGad g ex decrypt192 n cptr


--------------------- AES256 ---------------------------------------------------

instance Gadget (Ref256 Encryption) where
  type PrimitiveOf (Ref256 Encryption) = AES256 ECB Encryption
  type MemoryOf (Ref256 Encryption) = (CryptoCell Expanded256)
  newGadget cc = return $ Ref256 cc
  initialize (Ref256 ek) (AES256EIV k) = cellStore ek
                                         (expand256 $ fromByteString k)
  finalize _ = return AES256
  apply g@(Ref256 ex) n cptr = applyGad g ex encrypt256 n cptr

instance Gadget (Ref256 Decryption) where
  type PrimitiveOf (Ref256 Decryption) = AES256 ECB Decryption
  type MemoryOf (Ref256 Decryption) = (CryptoCell Expanded256)
  newGadget cc = return $ Ref256 cc
  initialize (Ref256 ek) (AES256DIV k) = cellStore ek
                                         (expand256 $ fromByteString k)
  finalize _ = return AES256
  apply g@(Ref256 ex) n cptr = applyGad g ex decrypt256 n cptr


applyGad :: (Gadget g, Storable k) => g
                                -> CryptoCell k
                                -> (STATE -> k -> STATE)
                                -> BLOCKS (PrimitiveOf g)
                                -> CryptoPtr
                                -> IO ()
applyGad g ex with n cptr = do
    expanded <- cellLoad ex
    foldM (moveAndHash expanded) cptr [1..n]
    return ()
    where
      getPrim :: Gadget g => g -> PrimitiveOf g
      getPrim _ = undefined
      sz = blockSize (getPrim g)
      moveAndHash expanded ptr _ = do
        blk <- peek (castPtr ptr)
        let newCxt = with blk expanded
        poke (castPtr ptr) newCxt
        return $ ptr `movePtr` sz
