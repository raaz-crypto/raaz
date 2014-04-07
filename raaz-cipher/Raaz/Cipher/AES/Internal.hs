{- |

This module exports internals of AES implementation and should not be
used directly by the user.

-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE FlexibleInstances  #-}
module Raaz.Cipher.AES.Internal
       ( AES(..)
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

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Data.Typeable

-- | AES Data type with associated modes.
data AES mode = AES deriving (Show, Eq)

instance HasName (Cipher (AES ECB) KEY128 Encryption) where
  getName _ = "AES128 ECB Encryption"

instance HasName (Cipher (AES ECB) KEY192 Encryption) where
  getName _ = "AES192 ECB Encryption"

instance HasName (Cipher (AES ECB) KEY256 Encryption) where
  getName _ = "AES256 ECB Encryption"

instance HasName (Cipher (AES ECB) KEY128 Decryption) where
  getName _ = "AES128 ECB Decryption"

instance HasName (Cipher (AES ECB) KEY192 Decryption) where
  getName _ = "AES192 ECB Decryption"

instance HasName (Cipher (AES ECB) KEY256 Decryption) where
  getName _ = "AES256 ECB Decryption"


instance HasName (Cipher (AES CBC) KEY128 Encryption) where
  getName _ = "AES128 CBC Encryption"

instance HasName (Cipher (AES CBC) KEY192 Encryption) where
  getName _ = "AES192 CBC Encryption"

instance HasName (Cipher (AES CBC) KEY256 Encryption) where
  getName _ = "AES256 CBC Encryption"

instance HasName (Cipher (AES CBC) KEY128 Decryption) where
  getName _ = "AES128 CBC Decryption"

instance HasName (Cipher (AES CBC) KEY192 Decryption) where
  getName _ = "AES192 CBC Decryption"

instance HasName (Cipher (AES CBC) KEY256 Decryption) where
  getName _ = "AES256 CBC Decryption"


instance HasName (Cipher (AES CTR) KEY128 Encryption) where
  getName _ = "AES128 CTR Encryption"

instance HasName (Cipher (AES CTR) KEY192 Encryption) where
  getName _ = "AES192 CTR Encryption"

instance HasName (Cipher (AES CTR) KEY256 Encryption) where
  getName _ = "AES256 CTR Encryption"

instance HasName (Cipher (AES CTR) KEY128 Decryption) where
  getName _ = "AES128 CTR Decryption"

instance HasName (Cipher (AES CTR) KEY192 Decryption) where
  getName _ = "AES192 CTR Decryption"

instance HasName (Cipher (AES CTR) KEY256 Decryption) where
  getName _ = "AES256 CTR Decryption"
