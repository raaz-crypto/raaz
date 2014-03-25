{- |

This module exports internals of AES implementation and should not be
used directly by the user.

-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies       #-}
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

import Raaz.Primitives.Cipher
import Data.Typeable

-- | AES Data type with associated modes.
data AES mode = AES deriving (Show, Eq, Typeable)
