{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.CBC.CPortable () where

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as BS
import           Foreign.Storable         (sizeOf)
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString     (withByteString, unsafeCopyToCryptoPtr)

import           Raaz.Cipher.AES.CBC.Type
import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: CryptoPtr  -- ^ expanded key
            -> CryptoPtr  -- ^ key
            -> Int        -- ^ Key type
            -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESCBCEncrypt"
  c_cbc_encrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESCBCDecrypt"
  c_cbc_decrypt  :: CryptoPtr  -- ^ expanded key
                 -> CryptoPtr  -- ^ Input
                 -> CryptoPtr  -- ^ IV
                 -> Int        -- ^ Number of Blocks
                 -> Int        -- ^ Key type
                 -> IO ()

--------------------- AES128 ---------------------------------------------------

instance Gadget (CPortable128 CBC Encryption) where
  type PrimitiveOf (CPortable128 CBC Encryption) = AES128 CBC Encryption
  type MemoryOf (CPortable128 CBC Encryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable128 cc
  initialize (CPortable128 (ek,civ)) (AES128EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 0
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_encrypt ekptr cptr ivptr (fromIntegral n) 0

instance Gadget (CPortable128 CBC Decryption) where
  type PrimitiveOf (CPortable128 CBC Decryption) = AES128 CBC Decryption
  type MemoryOf (CPortable128 CBC Decryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable128 cc
  initialize (CPortable128 (ek,civ)) (AES128DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 0
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_decrypt ekptr cptr ivptr (fromIntegral n) 0


--------------------- AES192 ---------------------------------------------------

instance Gadget (CPortable192 CBC Encryption) where
  type PrimitiveOf (CPortable192 CBC Encryption) = AES192 CBC Encryption
  type MemoryOf (CPortable192 CBC Encryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable192 cc
  initialize (CPortable192 (ek,civ)) (AES192EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 1
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_encrypt ekptr cptr ivptr (fromIntegral n) 1

instance Gadget (CPortable192 CBC Decryption) where
  type PrimitiveOf (CPortable192 CBC Decryption) = AES192 CBC Decryption
  type MemoryOf (CPortable192 CBC Decryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable192 cc
  initialize (CPortable192 (ek,civ)) (AES192DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 1
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_decrypt ekptr cptr ivptr (fromIntegral n) 1


--------------------- AES256 ---------------------------------------------------

instance Gadget (CPortable256 CBC Encryption) where
  type PrimitiveOf (CPortable256 CBC Encryption) = AES256 CBC Encryption
  type MemoryOf (CPortable256 CBC Encryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable256 cc
  initialize (CPortable256 (ek,civ)) (AES256EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 2
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_encrypt ekptr cptr ivptr (fromIntegral n) 2

instance Gadget (CPortable256 CBC Decryption) where
  type PrimitiveOf (CPortable256 CBC Decryption) = AES256 CBC Decryption
  type MemoryOf (CPortable256 CBC Decryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadgetWithMemory cc = return $ CPortable256 cc
  initialize (CPortable256 (ek,civ)) (AES256DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz expand
   where
     expand k inp = c_expand k inp 2
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_cbc_decrypt ekptr cptr ivptr (fromIntegral n) 2


initialWith :: (CryptoCell ek, CryptoCell STATE)
            -> (ByteString, ByteString)
            -> Int
            -> (CryptoPtr -> CryptoPtr -> IO ())
            -> IO ()
initialWith (ek,civ) (bsk,bsiv) sz with
  | BS.length bsk == sz && BS.length bsiv == blksz = do
    withCell ek (withByteString bsk . with)
    withCell civ (unsafeCopyToCryptoPtr bsiv)
  | otherwise = error "Unable to fill key with given data"
  where
    blksz = sizeOf (undefined :: STATE)
{-# INLINE initialWith #-}
