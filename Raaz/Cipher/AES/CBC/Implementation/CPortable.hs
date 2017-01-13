{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE FlexibleInstances                #-}
module Raaz.Cipher.AES.CBC.Implementation.CPortable
       ( aes128cbcI, aes192cbcI, aes256cbcI
       ) where

import Control.Applicative
import Control.Monad.IO.Class   ( liftIO )
import Foreign.Ptr              ( Ptr    )
import Prelude

import Raaz.Core
import Raaz.Cipher.Internal
import Raaz.Cipher.AES.Internal

------------- Memory for 128-bit cbc --------------

-- | Memory for aes-128-cbc
data M128 = M128 { m128ekey :: MemoryCell EKEY128
                 , m128iv   :: MemoryCell IV
                 }

instance Memory M128  where
  memoryAlloc     = M128 <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . m128ekey

instance Initialisable M128 (KEY128, IV) where
  initialise (k,iv) = do
    onSubMemory m128ekey $ do initialise k
                              withCellPointer $ c_transpose 11
    onSubMemory m128iv   $ do initialise iv
                              withCellPointer $ c_transpose 1

------------- Memory for 192-bit cbc --------------

-- | Memory for aes-192-cbc
data M192 = M192 { m192ekey :: MemoryCell EKEY192
                 , m192iv   :: MemoryCell IV
                 }

instance Memory M192  where
  memoryAlloc     = M192 <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . m192ekey

instance Initialisable M192 (KEY192, IV) where
  initialise (k,iv) = do
    onSubMemory m192ekey $ do initialise k
                              withCellPointer $ c_transpose 13
    onSubMemory m192iv   $ do initialise iv
                              withCellPointer $ c_transpose 1


------------- Memory for 256-bit cbc --------------

-- | Memory for aes-256-cbc
data M256 = M256 { m256ekey :: MemoryCell EKEY256
                 , m256iv   :: MemoryCell IV
                 }

instance Memory M256  where
  memoryAlloc     = M256 <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . m256ekey

instance Initialisable M256 (KEY256, IV) where
  initialise (k,iv) = do
    onSubMemory m256ekey $ do initialise k
                              withCellPointer $ c_transpose 15
    onSubMemory m256iv   $ do initialise iv
                              withCellPointer $ c_transpose 1

------------------- 128-bit CBC Implementation ----------------

-- | Implementation of 128-bit AES in CBC mode using Portable C.
aes128cbcI :: Implementation (AES 128 'CBC)
aes128cbcI = SomeCipherI cbc128CPortable

-- | 128-bit AES in CBC mode using Portable C.
cbc128CPortable :: CipherI (AES 128 'CBC) M128 M128
cbc128CPortable =
  CipherI { cipherIName = "aes128cbc-cportable"
          , cipherIDescription =
            "128-bit AES in cbc mode implemented in Portable C"
          , encryptBlocks = cbc128Encrypt
          , decryptBlocks = cbc128Decrypt
          , cipherStartAlignment = wordAlignment
          }

-- | The encryption action.
cbc128Encrypt :: Pointer -> BLOCKS (AES 128 'CBC) -> MT M128 ()
cbc128Encrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m128ekey getCellPointer
     ivPtr   <- onSubMemory m128iv   getCellPointer
     liftIO $ c_aes_cbc_e buf (fromEnum nBlocks) 10 eKeyPtr ivPtr

-- | The decryption action.
cbc128Decrypt :: Pointer -> BLOCKS (AES 128 'CBC) -> MT M128 ()
cbc128Decrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m128ekey getCellPointer
     ivPtr   <- onSubMemory m128iv   getCellPointer
     liftIO $ c_aes_cbc_d buf (fromEnum nBlocks) 10 eKeyPtr ivPtr



------------------- 192-bit CBC Implementation ----------------

-- | Implementation of 192-bit AES in CBC mode using Portable C.
aes192cbcI :: Implementation (AES 192 'CBC)
aes192cbcI = SomeCipherI cbc192CPortable

-- | 192-bit AES in CBC mode using Portable C.
cbc192CPortable :: CipherI (AES 192 'CBC) M192 M192
cbc192CPortable =
  CipherI { cipherIName = "aes192cbc-cportable"
          , cipherIDescription =
            "192-bit AES in cbc mode implemented in Portable C"
          , encryptBlocks = cbc192Encrypt
          , decryptBlocks = cbc192Decrypt
          , cipherStartAlignment = wordAlignment
          }

-- | The encryption action.
cbc192Encrypt :: Pointer -> BLOCKS (AES 192 'CBC) -> MT M192 ()
cbc192Encrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m192ekey getCellPointer
     ivPtr   <- onSubMemory m192iv   getCellPointer
     liftIO $ c_aes_cbc_e buf (fromEnum nBlocks) 12 eKeyPtr ivPtr

-- | The decryption action.
cbc192Decrypt :: Pointer -> BLOCKS (AES 192 'CBC) -> MT M192 ()
cbc192Decrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m192ekey getCellPointer
     ivPtr   <- onSubMemory m192iv   getCellPointer
     liftIO $ c_aes_cbc_d buf (fromEnum nBlocks) 12 eKeyPtr ivPtr

------------------- 256-bit CBC Implementation ----------------

-- | Implementation of 256-bit AES in CBC mode using Portable C.
aes256cbcI :: Implementation (AES 256 'CBC)
aes256cbcI = SomeCipherI cbc256CPortable

-- | 256-bit AES in CBC mode using Portable C.
cbc256CPortable :: CipherI (AES 256 'CBC) M256 M256
cbc256CPortable =
  CipherI { cipherIName = "aes256cbc-cportable"
          , cipherIDescription =
            "256-bit AES in cbc mode implemented in Portable C"
          , encryptBlocks = cbc256Encrypt
          , decryptBlocks = cbc256Decrypt
          , cipherStartAlignment = wordAlignment

          }

-- | The encryption action.
cbc256Encrypt :: Pointer -> BLOCKS (AES 256 'CBC) -> MT M256 ()
cbc256Encrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m256ekey getCellPointer
     ivPtr   <- onSubMemory m256iv   getCellPointer
     liftIO $ c_aes_cbc_e buf (fromEnum nBlocks) 14 eKeyPtr ivPtr

-- | The decryption action.
cbc256Decrypt :: Pointer -> BLOCKS (AES 256 'CBC) -> MT M256 ()
cbc256Decrypt buf nBlocks =
  do eKeyPtr <- onSubMemory m256ekey getCellPointer
     ivPtr   <- onSubMemory m256iv   getCellPointer
     liftIO $ c_aes_cbc_d buf (fromEnum nBlocks) 14 eKeyPtr ivPtr

--------------------- Foreign functions ------------------------

-- | Transpose AES matrices.
foreign import ccall unsafe
  "raaz/cipher/aes/common.h raazAESTranspose"
  c_transpose :: Int -> Ptr ekey -> IO ()


-- | CBC encrypt.
foreign import ccall unsafe
  "raaz/cipher/aes/cportable.h raazAESCBCEncryptCPortable"
  c_aes_cbc_e :: Pointer  -- Input
              -> Int      -- number of blocks
              -> Int      -- rounds
              -> Ptr ekey -- extended key
              -> Ptr iv   -- iv
              -> IO ()
-- | CBC decrypt
foreign import ccall unsafe
  "raaz/cipher/aes/cportable.h raazAESCBCDecryptCPortable"
  c_aes_cbc_d :: Pointer  -- Input
              -> Int      -- number of blocks
              -> Int      -- rounds
              -> Ptr ekey -- extened key
              -> Ptr iv  -- iv
              -> IO ()
