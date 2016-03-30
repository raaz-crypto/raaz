{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE FlexibleInstances                #-}
module Raaz.Cipher.AES.CBC.Implementation.CPortable
       ( aes128cbcI
       ) where

import Control.Applicative
import Control.Monad.IO.Class   ( liftIO )
import Raaz.Core
import Raaz.Cipher.Internal
import Raaz.Cipher.AES.Internal

------------- Memory for 128-bit cbc --------------

-- | Memory for aes-128-cbc
data M128 = M128 { m128ekey :: MemoryCell EKEY128
                 , m128iv   :: MemoryCell IV
                 }

instance Memory M128  where
  memoryAlloc   = M128 <$> memoryAlloc <*> memoryAlloc
  underlyingPtr = underlyingPtr . m128ekey

instance Initialisable M128 (KEY128, IV) where
  initialise (k,iv) = do
    liftSubMT m128ekey $ do initialise k
                            withPointer $ c_transpose 11
    liftSubMT m128iv   $ do initialise iv
                            withPointer $ c_transpose 1

foreign import ccall unsafe
  "raaz/cipher/aes/common.h raazAESTranspose"
  c_transpose :: Int -> Pointer -> IO ()


------------------- CBC Implementation -------------------------------

-- | Implementation of 128-bit AES in CBC mode using Portable C.
aes128cbcI :: Implementation (AES 128 CBC)
aes128cbcI = SomeCipherI cbc128CPortable

-- | 128-bit AES in CBC mode using Portable C.
cbc128CPortable :: CipherI (AES 128 CBC) M128 M128
cbc128CPortable =
  CipherI { cipherIName = "aes128cbc-cportable"
          , cipherIDescription =
            "128-bit AES in cbc mode implemented in Portable C"
          , encryptBlocks = cbc128Encrypt
          , decryptBlocks = cbc128Decrypt
          }

-- | The encryption action.
cbc128Encrypt :: Pointer -> BLOCKS (AES 128 CBC) -> MT M128 ()
cbc128Encrypt buf nBlocks =
  do eKeyPtr <- liftSubMT m128ekey getMemoryPointer
     ivPtr   <- liftSubMT m128iv   getMemoryPointer
     liftIO $ c_aes_cbc_e buf (fromEnum nBlocks) 10 eKeyPtr ivPtr

-- | The decryption action.
cbc128Decrypt :: Pointer -> BLOCKS (AES 128 CBC) -> MT M128 ()
cbc128Decrypt buf nBlocks =
  do eKeyPtr <- liftSubMT m128ekey getMemoryPointer
     ivPtr   <- liftSubMT m128iv   getMemoryPointer
     liftIO $ c_aes_cbc_d buf (fromEnum nBlocks) 10 eKeyPtr ivPtr

foreign import ccall unsafe
  "raaz/cipher/aes/cportable.h raazAESCBCEncryptCPortable"
  c_aes_cbc_e :: Pointer  -- Input
              -> Int      -- number of blocks
              -> Int      -- rounds
              -> Pointer  -- extended key
              -> Pointer  -- iv
              -> IO ()

foreign import ccall unsafe
  "raaz/cipher/aes/cportable.h raazAESCBCDecryptCPortable"
  c_aes_cbc_d :: Pointer  -- Input
              -> Int      -- number of blocks
              -> Int      -- rounds
              -> Pointer  -- extened key
              -> Pointer  -- iv
              -> IO ()