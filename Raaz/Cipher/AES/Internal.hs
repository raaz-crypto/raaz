{- |

This module exports internals of AES implementation and should not be
used directly by the user.

-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE CPP                #-}
{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# CFILES raaz/cipher/cportable/aes.c  #-}

module Raaz.Cipher.AES.Internal
       ( AES(..)
       , AESOp(..)
       , STATE(..)
       , KEY128(..)
       , KEY192(..)
       , KEY256(..)

       -- * These are exported for tests and should not be used directly.
       , encrypt128
       , encrypt192
       , encrypt256
       , decrypt128
       , decrypt192
       , decrypt256
       , HAESGadget(..), CAESGadget(..)
       ) where

import Control.Applicative
import Foreign.Storable           (sizeOf, Storable)


import Raaz.Core.Types
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Memory

import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.AES.Block.Internal

-- | AES Data type with associated modes.

data AES (mode :: CipherMode) key = AES deriving (Show, Eq)




-- | AES with the direction of operation.
data AESOp (mode :: CipherMode) key (op :: Mode) = AESOp deriving (Show, Eq)

{-
instance HasName (AESOp ECB KEY128 EncryptMode) where
  getName _ = "AES128 ECB EncryptMode"

instance HasName (AESOp ECB KEY192 EncryptMode) where
  getName _ = "AES192 ECB EncryptMode"

instance HasName (AESOp ECB KEY256 EncryptMode) where
  getName _ = "AES256 ECB EncryptMode"

instance HasName (AESOp ECB KEY128 DecryptMode) where
  getName _ = "AES128 ECB DecryptMode"

instance HasName (AESOp ECB KEY192 DecryptMode) where
  getName _ = "AES192 ECB DecryptMode"

instance HasName (AESOp ECB KEY256 DecryptMode) where
  getName _ = "AES256 ECB DecryptMode"


instance HasName (AESOp CBC KEY128 EncryptMode) where
  getName _ = "AES128 CBC EncryptMode"

instance HasName (AESOp CBC KEY192 EncryptMode) where
  getName _ = "AES192 CBC EncryptMode"

instance HasName (AESOp CBC KEY256 EncryptMode) where
  getName _ = "AES256 CBC EncryptMode"

instance HasName (AESOp CBC KEY128 DecryptMode) where
  getName _ = "AES128 CBC DecryptMode"

instance HasName (AESOp CBC KEY192 DecryptMode) where
  getName _ = "AES192 CBC DecryptMode"

instance HasName (AESOp CBC KEY256 DecryptMode) where
  getName _ = "AES256 CBC DecryptMode"


instance HasName (AESOp CTR KEY128 EncryptMode) where
  getName _ = "AES128 CTR EncryptMode"

instance HasName (AESOp CTR KEY192 EncryptMode) where
  getName _ = "AES192 CTR EncryptMode"

instance HasName (AESOp CTR KEY256 EncryptMode) where
  getName _ = "AES256 CTR EncryptMode"

instance HasName (AESOp CTR KEY128 DecryptMode) where
  getName _ = "AES128 CTR DecryptMode"

instance HasName (AESOp CTR KEY192 DecryptMode) where
  getName _ = "AES192 CTR DecryptMode"

instance HasName (AESOp CTR KEY256 DecryptMode) where
  getName _ = "AES256 CTR DecryptMode"

-}

----------------------------- Gadgets for AES -----------------------

type KeyCell k = MemoryCell (Expanded k)
type StateCell = MemoryCell STATE

data HAESGadget (mode :: CipherMode) key (op :: Mode) = HAESGadget (KeyCell key) StateCell
data CAESGadget (mode :: CipherMode) key (op :: Mode) = CAESGadget (KeyCell key) StateCell


---------------------------- HGadgets ------------------------------------

{--

instance HasName (HAESGadget CBC KEY128 EncryptMode) where
  getName _ = "HAES128 CBC EncryptMode"

instance HasName (HAESGadget CBC KEY192 EncryptMode) where
  getName _ = "HAES192 CBC EncryptMode"

instance HasName (HAESGadget CBC KEY256 EncryptMode) where
  getName _ = "HAES256 CBC EncryptMode"

instance HasName (HAESGadget CBC KEY128 DecryptMode) where
  getName _ = "HAES128 CBC DecryptMode"

instance HasName (HAESGadget CBC KEY192 DecryptMode) where
  getName _ = "HAES192 CBC DecryptMode"

instance HasName (HAESGadget CBC KEY256 DecryptMode) where
  getName _ = "HAES256 CBC DecryptMode"


instance HasName (HAESGadget CTR KEY128 EncryptMode) where
  getName _ = "HAES128 CTR EncryptMode"

instance HasName (HAESGadget CTR KEY192 EncryptMode) where
  getName _ = "HAES192 CTR EncryptMode"

instance HasName (HAESGadget CTR KEY256 EncryptMode) where
  getName _ = "HAES256 CTR EncryptMode"

instance HasName (HAESGadget CTR KEY128 DecryptMode) where
  getName _ = "HAES128 CTR DecryptMode"

instance HasName (HAESGadget CTR KEY192 DecryptMode) where
  getName _ = "HAES192 CTR DecryptMode"

instance HasName (HAESGadget CTR KEY256 DecryptMode) where
  getName _ = "HAES256 CTR DecryptMode"

--}

instance Storable (Expanded key) => Memory (HAESGadget mode key op) where

  memoryAlloc = HAESGadget <$> memoryAlloc <*> memoryAlloc

  underlyingPtr (HAESGadget kC _) = underlyingPtr kC


instance InitializableMemory (HAESGadget mode KEY128 op) where

  type IV (HAESGadget mode KEY128 op) = (KEY128, STATE)

  initializeMemory (HAESGadget kC stC) (k,s) = cExpand128 k kC
                                             >> withCell stC (flip store s)


instance InitializableMemory (HAESGadget mode KEY192 op) where

  type IV (HAESGadget mode KEY192 op) = (KEY192, STATE)

  initializeMemory (HAESGadget kC stC) (k,s) = cExpand192 k kC
                                             >> withCell stC (flip store s)


instance InitializableMemory (HAESGadget mode KEY256 op) where

  type IV (HAESGadget mode KEY256 op) = (KEY256, STATE)

  initializeMemory (HAESGadget kC stC) (k,s) = cExpand256 k kC
                                             >> withCell stC (flip store s)


--------------------- C Gadgets -------------------------------------------

{--
instance HasName (CAESGadget CBC KEY128 EncryptMode) where
  getName _ = "CAES128 CBC EncryptMode"

instance HasName (CAESGadget CBC KEY192 EncryptMode) where
  getName _ = "CAES192 CBC EncryptMode"

instance HasName (CAESGadget CBC KEY256 EncryptMode) where
  getName _ = "CAES256 CBC EncryptMode"

instance HasName (CAESGadget CBC KEY128 DecryptMode) where
  getName _ = "CAES128 CBC DecryptMode"

instance HasName (CAESGadget CBC KEY192 DecryptMode) where
  getName _ = "CAES192 CBC DecryptMode"

instance HasName (CAESGadget CBC KEY256 DecryptMode) where
  getName _ = "CAES256 CBC DecryptMode"


instance HasName (CAESGadget CTR KEY128 EncryptMode) where
  getName _ = "CAES128 CTR EncryptMode"

instance HasName (CAESGadget CTR KEY192 EncryptMode) where
  getName _ = "CAES192 CTR EncryptMode"

instance HasName (CAESGadget CTR KEY256 EncryptMode) where
  getName _ = "CAES256 CTR EncryptMode"

instance HasName (CAESGadget CTR KEY128 DecryptMode) where
  getName _ = "CAES128 CTR DecryptMode"

instance HasName (CAESGadget CTR KEY192 DecryptMode) where
  getName _ = "CAES192 CTR DecryptMode"

instance HasName (CAESGadget CTR KEY256 DecryptMode) where
  getName _ = "CAES256 CTR DecryptMode"

--}

instance Storable (Expanded key) => Memory (CAESGadget mode key op) where

  memoryAlloc = CAESGadget <$> memoryAlloc <*> memoryAlloc

  underlyingPtr (CAESGadget kC _) = underlyingPtr kC



instance InitializableMemory (CAESGadget mode KEY128 op) where

  type IV (CAESGadget mode KEY128 op) = (KEY128, STATE)

  initializeMemory (CAESGadget kC stC) (k,s) = cExpand128 k kC
                                             >> withCell stC (flip store s)


instance InitializableMemory (CAESGadget mode KEY192 op) where

  type IV (CAESGadget mode KEY192 op) = (KEY192, STATE)

  initializeMemory (CAESGadget kC stC) (k,s) = cExpand192 k kC
                                             >> withCell stC (flip store s)


instance InitializableMemory (CAESGadget mode KEY256 op) where

  type IV (CAESGadget mode KEY256 op) = (KEY256, STATE)

  initializeMemory (CAESGadget kC stC) (k,s) = cExpand256 k kC
                                             >> withCell stC (flip store s)


-------------------- Helper functions and ffi --------------------------


-- | SECURITY LOOPHOLE TO FIX. Memory allocated through `allocaBuffer`
-- is not a secureMemory and would not be scrubbed. The alternative to
-- fix this is to change the context to a Memory containing Key
-- instead of pure Key (similar for IV) and that memory should be
-- passed while interfacing with C code.
cExpansionWith :: (EndianStore k, Storable ek)
               => MemoryCell ek
               -> k
               -> (Pointer -> Pointer -> Int -> IO ())
               -> Int
               -> IO ()
cExpansionWith ek k with i = allocaBuffer szk $ \kptr -> do
  store kptr k
  withCell ek $ expnd kptr
  where
    expnd kptr ekptr = with ekptr kptr i
    szk :: BYTES Int
    szk = BYTES $ sizeOf k
{-# INLINE cExpansionWith #-}

cExpand128 :: KEY128 -> MemoryCell (Expanded KEY128) -> IO ()
cExpand128 k excell = cExpansionWith excell k c_expand 0

cExpand192 :: KEY192 -> MemoryCell (Expanded KEY192) -> IO ()
cExpand192 k excell = cExpansionWith excell k c_expand 1

cExpand256 :: KEY256 -> MemoryCell (Expanded KEY256) -> IO ()
cExpand256 k excell = cExpansionWith excell k c_expand 2


foreign import ccall unsafe
  "raaz/cipher/cportable/aes.c raazCipherAESExpand"
  c_expand  :: Pointer  -- ^ expanded key
            -> Pointer  -- ^ key
            -> Int        -- ^ Key type
            -> IO ()
