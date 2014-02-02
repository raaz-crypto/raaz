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
import Raaz.Cipher.AES.Ref.Internal
import Raaz.Cipher.AES.Internal

--------------------- AES128 ---------------------------------------------------

instance Gadget (Ref128 ECB Encryption) where
  type PrimitiveOf (Ref128 ECB Encryption) = AES128 ECB Encryption
  type MemoryOf (Ref128 ECB Encryption) = (CryptoCell Expanded128)
  newGadgetWithMemory cc = return $ Ref128 (cc,undefined)
  initialize (Ref128 (ek,_)) (AES128EIV k) = cellStore ek
                                         (expand128 $ fromByteString k)
  finalize _ = return AES128
  apply g@(Ref128 (ex,_)) = applyGad g ex encrypt128

instance Gadget (Ref128 ECB Decryption) where
  type PrimitiveOf (Ref128 ECB Decryption) = AES128 ECB Decryption
  type MemoryOf (Ref128 ECB Decryption) = (CryptoCell Expanded128)
  newGadgetWithMemory cc = return $ Ref128 (cc,undefined)
  initialize (Ref128 (ek,_)) (AES128DIV k) = cellStore ek
                                         (expand128 $ fromByteString k)
  finalize _ = return AES128
  apply g@(Ref128 (ex,_)) = applyGad g ex decrypt128


--------------------- AES192 ---------------------------------------------------

instance Gadget (Ref192 ECB Encryption) where
  type PrimitiveOf (Ref192 ECB Encryption) = AES192 ECB Encryption
  type MemoryOf (Ref192 ECB Encryption) = (CryptoCell Expanded192)
  newGadgetWithMemory cc = return $ Ref192 (cc,undefined)
  initialize (Ref192 (ek,_)) (AES192EIV k) = cellStore ek
                                         (expand192 $ fromByteString k)
  finalize _ = return AES192
  apply g@(Ref192 (ex,_)) = applyGad g ex encrypt192

instance Gadget (Ref192 ECB Decryption) where
  type PrimitiveOf (Ref192 ECB Decryption) = AES192 ECB Decryption
  type MemoryOf (Ref192 ECB Decryption) = (CryptoCell Expanded192)
  newGadgetWithMemory cc = return $ Ref192 (cc,undefined)
  initialize (Ref192 (ek,_)) (AES192DIV k) = cellStore ek
                                         (expand192 $ fromByteString k)
  finalize _ = return AES192
  apply g@(Ref192 (ex,_)) = applyGad g ex decrypt192


--------------------- AES256 ---------------------------------------------------

instance Gadget (Ref256 ECB Encryption) where
  type PrimitiveOf (Ref256 ECB Encryption) = AES256 ECB Encryption
  type MemoryOf (Ref256 ECB Encryption) = (CryptoCell Expanded256)
  newGadgetWithMemory cc = return $ Ref256 (cc,undefined)
  initialize (Ref256 (ek,_)) (AES256EIV k) = cellStore ek
                                         (expand256 $ fromByteString k)
  finalize _ = return AES256
  apply g@(Ref256 (ex,_)) = applyGad g ex encrypt256

instance Gadget (Ref256 ECB Decryption) where
  type PrimitiveOf (Ref256 ECB Decryption) = AES256 ECB Decryption
  type MemoryOf (Ref256 ECB Decryption) = (CryptoCell Expanded256)
  newGadgetWithMemory cc = return $ Ref256 (cc,undefined)
  initialize (Ref256 (ek,_)) (AES256DIV k) = cellStore ek
                                         (expand256 $ fromByteString k)
  finalize _ = return AES256
  apply g@(Ref256 (ex,_)) = applyGad g ex decrypt256


applyGad :: (Gadget g, Storable k) => g
                                -> CryptoCell k
                                -> (STATE -> k -> STATE)
                                -> BLOCKS (PrimitiveOf g)
                                -> CryptoPtr
                                -> IO ()
applyGad g ex with n cptr = do
    expanded <- cellLoad ex
    void $ foldM (moveAndHash expanded) cptr [1..n]
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
