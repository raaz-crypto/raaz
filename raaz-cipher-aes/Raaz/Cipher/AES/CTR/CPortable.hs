{-# LANGUAGE DataKinds                #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# LANGUAGE TypeFamilies             #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Cipher.AES.CTR.CPortable () where

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as BS
import           Foreign.Storable         (sizeOf)
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString     (withByteString, unsafeCopyToCryptoPtr)

import           Raaz.Cipher.AES.CTR.Type
import           Raaz.Cipher.AES.Ref.Type
import           Raaz.Cipher.AES.Type

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand128"
  c_expand128  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand192"
  c_expand192  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand256"
  c_expand256  :: CryptoPtr  -- ^ expanded key
               -> CryptoPtr  -- ^ key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptCTR128"
  c_ctr_encrypt128  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> CryptoPtr  -- ^ IV
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptCTR192"
  c_ctr_encrypt192  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> CryptoPtr  -- ^ IV
                    -> Int        -- ^ Number of Blocks
                    -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESEncryptCTR256"
  c_ctr_encrypt256  :: CryptoPtr  -- ^ expanded key
                    -> CryptoPtr  -- ^ Input
                    -> CryptoPtr  -- ^ IV
                    -> Int        -- ^ Number of Blocks
                    -> IO ()


--------------------- AES128 ---------------------------------------------------

instance Gadget (CPortable128 Encryption) where
  type PrimitiveOf (CPortable128 Encryption) = AES128 CTR Encryption
  type MemoryOf (CPortable128 Encryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadget cc = return $ CPortable128 cc
  initialize (CPortable128 (ek,civ)) (AES128EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand128
   where
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt128 ekptr cptr ivptr (fromIntegral n)

instance Gadget (CPortable128 Decryption) where
  type PrimitiveOf (CPortable128 Decryption) = AES128 CTR Decryption
  type MemoryOf (CPortable128 Decryption) = (CryptoCell Expanded128, CryptoCell STATE)
  newGadget cc = return $ CPortable128 cc
  initialize (CPortable128 (ek,civ)) (AES128DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand128
   where
     sz = sizeOf (undefined :: KEY128)
  finalize _ = return AES128
  apply (CPortable128 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt128 ekptr cptr ivptr (fromIntegral n)


--------------------- AES192 ---------------------------------------------------

instance Gadget (CPortable192 Encryption) where
  type PrimitiveOf (CPortable192 Encryption) = AES192 CTR Encryption
  type MemoryOf (CPortable192 Encryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadget cc = return $ CPortable192 cc
  initialize (CPortable192 (ek,civ)) (AES192EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand192
   where
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt192 ekptr cptr ivptr (fromIntegral n)

instance Gadget (CPortable192 Decryption) where
  type PrimitiveOf (CPortable192 Decryption) = AES192 CTR Decryption
  type MemoryOf (CPortable192 Decryption) = (CryptoCell Expanded192, CryptoCell STATE)
  newGadget cc = return $ CPortable192 cc
  initialize (CPortable192 (ek,civ)) (AES192DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand192
   where
     sz = sizeOf (undefined :: KEY192)
  finalize _ = return AES192
  apply (CPortable192 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt192 ekptr cptr ivptr (fromIntegral n)


--------------------- AES256 ---------------------------------------------------

instance Gadget (CPortable256 Encryption) where
  type PrimitiveOf (CPortable256 Encryption) = AES256 CTR Encryption
  type MemoryOf (CPortable256 Encryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadget cc = return $ CPortable256 cc
  initialize (CPortable256 (ek,civ)) (AES256EIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand256
   where
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt256 ekptr cptr ivptr (fromIntegral n)

instance Gadget (CPortable256 Decryption) where
  type PrimitiveOf (CPortable256 Decryption) = AES256 CTR Decryption
  type MemoryOf (CPortable256 Decryption) = (CryptoCell Expanded256, CryptoCell STATE)
  newGadget cc = return $ CPortable256 cc
  initialize (CPortable256 (ek,civ)) (AES256DIV (bs,iv)) =
    initialWith (ek,civ) (bs,iv) sz c_expand256
   where
     sz = sizeOf (undefined :: KEY256)
  finalize _ = return AES256
  apply (CPortable256 (ek,civ)) n cptr = withCell ek (withCell civ . doStuff)
    where
      doStuff ekptr ivptr = c_ctr_encrypt256 ekptr cptr ivptr (fromIntegral n)


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
