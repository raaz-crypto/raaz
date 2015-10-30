{- |

This module exports internals of Salsa20 implementation and should not
be used directly by the user.

-}

{-# LANGUAGE FlexibleInstances             #-}
{-# LANGUAGE TypeFamilies                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving    #-}
{-# LANGUAGE DataKinds                     #-}
{-# LANGUAGE CPP                           #-}
{-# LANGUAGE ForeignFunctionInterface      #-}


module Raaz.Cipher.Salsa20.Internal
       ( Salsa20(..)
       , Rounds(..)
       , KEY128
       , KEY256
       , Nonce
       , Counter
         -- * This is exported for tests and should not be used directly.
       , Matrix(..)
       , STATE(..)
       , module Raaz.Cipher.Salsa20.Block.Internal
       ) where

import Raaz.Core.Primitives.Cipher        ()
import Raaz.Core.Types

import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Block.Internal

-- | Salsa20 with given rounds
data Salsa20 (rounds :: Rounds) key = Salsa20 deriving (Show, Eq)

-- | Rounds in Salsa20 core
data Rounds = R20
            | R12
            | R8


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
