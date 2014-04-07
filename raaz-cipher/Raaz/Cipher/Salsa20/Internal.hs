{- |

This module exports internals of Salsa20 implementation and should not
be used directly by the user.

-}

{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE CPP                #-}
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
         -- * This is exported for tests and should not be used directly.
       , Matrix(..)
       , STATE(..)
       , module Raaz.Cipher.Salsa20.Block.Internal
       ) where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Block.Internal

-- | Salsa20 with given rounds
#if UseKinds
data Salsa20 (r :: Rounds) = Salsa20 deriving (Show, Eq)

-- | Rounds in Salsa20 core
data Rounds = R20
            | R12
            | R8
#else
data Salsa20 r = Salsa20 deriving (Show, Eq)

-- | 20 Rounds
data R20 = R20 deriving (Show, Eq)

-- | 12 Rounds
data R12 = R12 deriving (Show, Eq)

-- | 8 Rounds
data R8  = R8 deriving (Show, Eq)
#endif

instance HasName (Cipher (Salsa20 R20) KEY128 Encryption) where
  getName _ = "Salsa20/20 KEY128 Encryption"

instance HasName (Cipher (Salsa20 R20) KEY256 Encryption) where
  getName _ = "Salsa20/20 KEY256 Encryption"

instance HasName (Cipher (Salsa20 R20) KEY128 Decryption) where
  getName _ = "Salsa20/20 KEY128 Decryption"

instance HasName (Cipher (Salsa20 R20) KEY256 Decryption) where
  getName _ = "Salsa20/20 KEY256 Decryption"

instance HasName (Cipher (Salsa20 R12) KEY128 Encryption) where
  getName _ = "Salsa20/12 KEY128 Encryption"

instance HasName (Cipher (Salsa20 R12) KEY256 Encryption) where
  getName _ = "Salsa20/12 KEY256 Encryption"

instance HasName (Cipher (Salsa20 R12) KEY128 Decryption) where
  getName _ = "Salsa20/12 KEY128 Decryption"

instance HasName (Cipher (Salsa20 R12) KEY256 Decryption) where
  getName _ = "Salsa20/12 KEY256 Decryption"

instance HasName (Cipher (Salsa20 R8) KEY128 Encryption) where
  getName _ = "Salsa20/8 KEY128 Encryption"

instance HasName (Cipher (Salsa20 R8) KEY256 Encryption) where
  getName _ = "Salsa20/8 KEY256 Encryption"

instance HasName (Cipher (Salsa20 R8) KEY128 Decryption) where
  getName _ = "Salsa20/8 KEY128 Decryption"

instance HasName (Cipher (Salsa20 R8) KEY256 Decryption) where
  getName _ = "Salsa20/8 KEY256 Decryption"
