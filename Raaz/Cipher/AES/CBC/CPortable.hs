{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE DataKinds                 #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/cipher/cportable/aes.c #-}

module Raaz.Cipher.AES.CBC.CPortable () where

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Cipher.AES.CBC.Type       ()
import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.AES.Internal

------------------------  Gadgets alias ----------------

-- The encryption gadget
type EncryptG key = CAESGadget CBC key EncryptMode

-- The decryption gadget type
type DecryptG key = CAESGadget CBC key DecryptMode

----------------------- KEY128 CBC ----------------------

instance Gadget    (EncryptG KEY128) where
  type PrimitiveOf (EncryptG KEY128) = AES CBC KEY128
  apply                              = loadAndApply c_cbc_encrypt 0

instance Gadget (DecryptG KEY128) where
  type PrimitiveOf (DecryptG KEY128) = AES CBC KEY128
  apply                              = loadAndApply c_cbc_decrypt 0

----------------------- KEY192 CBC ----------------------

instance Gadget    (EncryptG KEY192) where
  type PrimitiveOf (EncryptG KEY192) = AES CBC KEY192
  apply                              = loadAndApply c_cbc_encrypt 1

instance Gadget (DecryptG KEY192) where
  type PrimitiveOf (DecryptG KEY192) = AES CBC KEY192
  apply                              = loadAndApply c_cbc_decrypt 1

------------------------ KEY256 CBC ------------------------

instance Gadget    (EncryptG KEY256) where
  type PrimitiveOf (EncryptG KEY256) = AES CBC KEY256
  apply                              = loadAndApply c_cbc_encrypt 2

instance Gadget (DecryptG KEY256) where
  type PrimitiveOf (DecryptG KEY256) = AES CBC KEY256
  apply                              = loadAndApply c_cbc_decrypt 2

----------------------------- Helper function ----------------------------------------------

loadAndApply :: (CryptoPtr -> CryptoPtr -> CryptoPtr -> Int -> Int -> IO ())
             -> Int
             -> CAESGadget CBC key op
             -> BLOCKS (AES CBC key)
             -> CryptoPtr
             -> IO ()
loadAndApply encrypt i (CAESGadget  kC stC) n cptr = withCell kC (withCell stC . doStuff)
    where
      doStuff ekptr ivptr = encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}

----------------------------- Foreign function calls -----------------------------------------

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.h raazCipherAESCBCEncrypt"
  c_cbc_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.h raazCipherAESCBCDecrypt"
  c_cbc_decrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()
