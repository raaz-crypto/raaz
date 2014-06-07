{- |

This module exports internals of AES implementation and should not be
used directly by the user.

-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE CPP                #-}
module Raaz.Cipher.AES.Internal
       ( AES(..)
       , AESOp(..)
       , STATE(..)
       , KEY128(..)
       , KEY192(..)
       , KEY256(..)

       -- * These are exported for tests and should not be used directly.
       , expand128
       , expand192
       , expand256
       , encrypt128
       , encrypt192
       , encrypt256
       , decrypt128
       , decrypt192
       , decrypt256
       ) where

import Raaz.Cipher.AES.Block.Type
import Raaz.Cipher.AES.Block.Internal

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher

-- | AES Data type with associated modes.
#if UseKinds
data AES (mode :: CipherMode) key = AES deriving (Show, Eq)
#else
data AES mode key = AES deriving (Show, Eq)

{-# DEPRECATED AES
  "Mode will be kind restricted from ghc7.6 onwards" #-}
#endif

-- | AES with the direction of operation.
#if UseKinds
data AESOp (mode :: CipherMode) key (op :: Mode) = AESOp deriving (Show, Eq)
#else
data AESOp mode key op = AESOp deriving (Show, Eq)

{-# DEPRECATED AESOp
  "mode and op will be kind restricted from ghc7.6 onwards" #-}
#endif

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
