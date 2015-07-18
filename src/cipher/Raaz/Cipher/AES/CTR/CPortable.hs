{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.CTR.CPortable () where

import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types

import           Raaz.Cipher.AES.CTR.Type ()
import           Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.h raazCipherAESCTREncrypt"
  c_ctr_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key Type
                 -> IO ()


------------------------  Gadgets alias ----------------

-- The encryption gadget
type CTRG key = CAESGadget CTR key EncryptMode

instance Gadget (CTRG KEY128) where
  type PrimitiveOf (CTRG KEY128) = AES CTR KEY128
  apply = loadAndApply 0

instance Gadget (CTRG KEY192) where
  type PrimitiveOf (CTRG KEY192) = AES CTR KEY192
  apply = loadAndApply 1

instance Gadget (CTRG KEY256) where
  type PrimitiveOf (CTRG KEY256) = AES CTR KEY256
  apply = loadAndApply 2

loadAndApply :: Int -> (CTRG key)
             -> BLOCKS (AES CTR key)
             -> CryptoPtr
             -> IO ()
loadAndApply i (CAESGadget kC stC) n cptr = withCell kC (withCell stC . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt ekptr cptr ivptr (fromIntegral n) i
{-# INLINE loadAndApply #-}
