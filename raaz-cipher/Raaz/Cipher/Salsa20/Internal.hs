{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.Cipher.Salsa20.Internal
       ( module Raaz.Cipher.Salsa20.Block.Type
       , module Raaz.Primitives.Cipher
       , module Raaz.Cipher.Salsa20.Block.Internal
       , Salsa20(..)
       , R20(..)
       , R12(..)
       , R8(..)
       ) where

import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Block.Internal

import Raaz.Primitives.Cipher
import Data.Typeable
import Raaz.Primitives

-- | Salsa20 with given rounds
data Salsa20 r = Salsa20 deriving (Show, Eq, Typeable)

-- | 20 Rounds
data R20 = R20 deriving (Show, Eq, Typeable)

-- | 12 Rounds
data R12 = R12 deriving (Show, Eq, Typeable)

-- | 8 Rounds
data R8  = R8 deriving (Show, Eq, Typeable)
