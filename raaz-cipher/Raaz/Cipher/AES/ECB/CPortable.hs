{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.ECB.CPortable () where

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as BS
import           Foreign.Storable         (sizeOf)
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString     (withByteString)

import           Raaz.Cipher.AES.ECB.Type
import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: CryptoPtr  -- ^ expanded key
            -> CryptoPtr  -- ^ key
            -> Int        -- ^ key type => 0 - 128, 1 - 192, 2 - 256
            -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESECBEncrypt"
  c_ecb_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESECBDecrypt"
  c_ecb_decrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

--------------------- AES128 ---------------------------------------------------

instance Gadget (CPortable128 ECB Encryption) where
  type PrimitiveOf (CPortable128 ECB Encryption) = AES128 ECB Encryption
  type MemoryOf (CPortable128 ECB Encryption) = (CryptoCell Expanded128)
  newGadgetWithMemory cc = return $ CPortable128 (cc, undefined)
  initialize (CPortable128 (ek,_)) (AES128EIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 0
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 0

instance Gadget (CPortable128 ECB Decryption) where
  type PrimitiveOf (CPortable128 ECB Decryption) = AES128 ECB Decryption
  type MemoryOf (CPortable128 ECB Decryption) = (CryptoCell Expanded128)
  newGadgetWithMemory cc = return $ CPortable128 (cc, undefined)
  initialize (CPortable128 (ek,_)) (AES128DIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 0
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 0


--------------------- AES192 ---------------------------------------------------

instance Gadget (CPortable192 ECB Encryption) where
  type PrimitiveOf (CPortable192 ECB Encryption) = AES192 ECB Encryption
  type MemoryOf (CPortable192 ECB Encryption) = (CryptoCell Expanded192)
  newGadgetWithMemory cc = return $ CPortable192 (cc,undefined)
  initialize (CPortable192 (ek,_)) (AES192EIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 1
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 1

instance Gadget (CPortable192 ECB Decryption) where
  type PrimitiveOf (CPortable192 ECB Decryption) = AES192 ECB Decryption
  type MemoryOf (CPortable192 ECB Decryption) = (CryptoCell Expanded192)
  newGadgetWithMemory cc = return $ CPortable192 (cc, undefined)
  initialize (CPortable192 (ek,_)) (AES192DIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 1
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 1


--------------------- AES256 ---------------------------------------------------

instance Gadget (CPortable256 ECB Encryption) where
  type PrimitiveOf (CPortable256 ECB Encryption) = AES256 ECB Encryption
  type MemoryOf (CPortable256 ECB Encryption) = (CryptoCell Expanded256)
  newGadgetWithMemory cc = return $ CPortable256 (cc,undefined)
  initialize (CPortable256 (ek,_)) (AES256EIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 2
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_encrypt ekptr cptr (fromIntegral n) 2

instance Gadget (CPortable256 ECB Decryption) where
  type PrimitiveOf (CPortable256 ECB Decryption) = AES256 ECB Decryption
  type MemoryOf (CPortable256 ECB Decryption) = (CryptoCell Expanded256)
  newGadgetWithMemory cc = return $ CPortable256 (cc,undefined)
  initialize (CPortable256 (ek,_)) (AES256DIV bs) = initialWith ek bs sz expand
   where
     expand k inp = c_expand k inp 2
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,_)) n cptr = withCell ek doStuff
    where
      doStuff ekptr = c_ecb_decrypt ekptr cptr (fromIntegral n) 2


initialWith :: CryptoCell ek
            -> ByteString
            -> Int
            -> (CryptoPtr -> CryptoPtr -> IO ())
            -> IO ()
initialWith ek bs sz with | BS.length bs == sz = withCell ek (withByteString bs . with)
                          | otherwise          = error "Unable to fill key with given data"
{-# INLINE initialWith #-}
