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
