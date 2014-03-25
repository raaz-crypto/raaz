{- |

This module exports internals of Salsa20 implementation and should not
be used directly by the user.

-}

{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.Cipher.Salsa20.Internal
       ( Salsa20
       , R20
       , R12
       , R8
       , KEY128
       , KEY256
       , Nonce
       , Counter
         -- * This is exported for tests and should not be used directly.
       , Matrix(..)
       , STATE(..)
       , module Raaz.Cipher.Salsa20.Block.Internal
       ) where

import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Block.Internal

import Data.Typeable

-- | Salsa20 with given rounds
data Salsa20 r = Salsa20 deriving (Show, Eq, Typeable)

-- | 20 Rounds
data R20 = R20 deriving (Show, Eq, Typeable)

-- | 12 Rounds
data R12 = R12 deriving (Show, Eq, Typeable)

-- | 8 Rounds
data R8  = R8 deriving (Show, Eq, Typeable)
