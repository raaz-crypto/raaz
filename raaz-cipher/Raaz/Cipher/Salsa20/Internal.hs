{- |

This module exports internals of Salsa20 implementation and should not
be used directly by the user.

-}

{-# LANGUAGE KindSignatures                #-}
{-# LANGUAGE FlexibleInstances             #-}
{-# LANGUAGE TypeFamilies                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving    #-}
{-# LANGUAGE CPP                           #-}
{-# LANGUAGE ForeignFunctionInterface      #-}
{-# CFILES raaz/cipher/cportable/salsa20.c #-}

module Raaz.Cipher.Salsa20.Internal
       ( Salsa20(..)
#if UseKinds
       , Rounds(..)
#else
       , R20(..)
       , R12(..)
       , R8(..)
#endif
       , KEY128
       , KEY256
       , Nonce
       , Counter
       , SalsaMem(..)
         -- * This is exported for tests and should not be used directly.
       , Matrix(..)
       , STATE(..)
       , module Raaz.Cipher.Salsa20.Block.Internal
       ) where

import Foreign.Ptr
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher        ()
import Raaz.Core.Types
import Raaz.Core.Util.Ptr                 (allocaBuffer)

import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Block.Internal

-- | Salsa20 with given rounds
#if UseKinds
data Salsa20 (rounds :: Rounds) key = Salsa20 deriving (Show, Eq)

-- | Rounds in Salsa20 core
data Rounds = R20
            | R12
            | R8
#else
data Salsa20 rounds key = Salsa20 deriving (Show, Eq)

{-# DEPRECATED Salsa20
  "Kind restrictions will be used in rounds from ghc7.6 onwards" #-}

-- | 20 Rounds
data R20 = R20 deriving (Show, Eq)

-- | 12 Rounds
data R12 = R12 deriving (Show, Eq)

-- | 8 Rounds
data R8  = R8 deriving (Show, Eq)

{-# DEPRECATED R20, R12, R8
  "Will be changed to Data Constructor of type Rounds from ghc7.6 onwards" #-}
#endif

-- | Memory used in Salsa20 Implementations. It uses the C expansion
-- for expanding the key.
newtype SalsaMem k = SalsaMem (CryptoCell Matrix) deriving Memory

instance InitializableMemory (SalsaMem KEY128) where
  type IV (SalsaMem KEY128) = (KEY128, Nonce)

  initializeMemory (SalsaMem cell) (k,n) = cExpand128 cell k n counter0

instance InitializableMemory (SalsaMem KEY256) where
  type IV (SalsaMem KEY256) = (KEY256, Nonce)

  initializeMemory (SalsaMem cell) (k,n) = cExpand256 cell k n counter0

counter0 :: Counter
counter0 = Counter (SplitWord64 0 0)

instance HasName (Salsa20 R20 KEY128) where
  getName _ = "Salsa20/20 KEY128"

instance HasName (Salsa20 R20 KEY256) where
  getName _ = "Salsa20/20 KEY256"

instance HasName (Salsa20 R12 KEY128) where
  getName _ = "Salsa20/12 KEY128"

instance HasName (Salsa20 R12 KEY256) where
  getName _ = "Salsa20/12 KEY256"

instance HasName (Salsa20 R8 KEY128) where
  getName _ = "Salsa20/8 KEY128"

instance HasName (Salsa20 R8 KEY256) where
  getName _ = "Salsa20/8 KEY256"

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c expand128"
  c_expand128  :: CryptoPtr -- ^ IV = (Key || Nonce || Counter)
               -> CryptoPtr -- ^ expanded key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c expand256"
  c_expand256  :: CryptoPtr  -- ^ IV = (Key || Nonce || Counter)
               -> CryptoPtr  -- ^ expanded key
               -> IO ()

-- | SECURITY LOOPHOLE. Read similar function in AES for description
-- of the problem.
cExpansionWith :: EndianStore k
                => (CryptoPtr -> CryptoPtr -> IO ())
                -> CryptoCell Matrix
                -> k
                -> Nonce
                -> Counter
                -> IO ()
cExpansionWith with mc key nonce cntr = withCell mc (expand key nonce  cntr)
  where
    szk = BYTES $ sizeOf key + sizeOf nonce + sizeOf cntr
    expand k n c mptr = allocaBuffer szk $ \tempptr -> do
      store tempptr k
      let tempptrn = tempptr `plusPtr` sizeOf k
      store tempptrn n
      let tempptrc = tempptrn `plusPtr` sizeOf n
      store tempptrc c
      with tempptr mptr
{-# INLINE cExpansionWith #-}

cExpand128 :: CryptoCell Matrix -> KEY128 -> Nonce -> Counter -> IO ()
cExpand128 = cExpansionWith c_expand128
{-# INLINE cExpand128 #-}

cExpand256 :: CryptoCell Matrix -> KEY256 -> Nonce -> Counter -> IO ()
cExpand256 = cExpansionWith c_expand256
{-# INLINE cExpand256 #-}
