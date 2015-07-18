{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FunctionalDependencies     #-}
module Raaz.KeyExchange
       ( SharedSecret(..)
       , PublicNum(..)
       , PrivateNum(..)
       , KeyExchange(..)
       ) where


import Raaz.Number
import Raaz.Random
import Raaz.Core.Primitives.Cipher

import Foreign.Storable

-- | Shared Secret
newtype SharedSecret w = SharedSecret w
                       deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)

-- | Public key
newtype PublicNum w = PublicNum w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)

-- | Private key
newtype PrivateNum w = PrivateNum w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)

class (Modular w, Integral w) => KeyExchange k w | k -> w where

  -- | Generate random public and private numbers.
  generate :: StreamGadget g
           => k -> RandomSource g -> IO (PrivateNum w, PublicNum w)

  -- | Get shared secret from public and private numbers
  getSecret :: k -> PrivateNum w -> PublicNum w -> SharedSecret w
