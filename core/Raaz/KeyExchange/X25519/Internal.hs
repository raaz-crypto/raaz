{-# LANGUAGE DataKinds                   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleInstances           #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE TypeFamilies                #-}
module Raaz.KeyExchange.X25519.Internal
       ( X25519(..)
       ) where

import Foreign.Storable
import Raaz.Core
import Raaz.Core.KeyExchange ()

data X25519 = X25519

type Word256 = Tuple 4 (LE Word64)

instance KeyExchange X25519 where

  newtype Private X25519 = Private Word256
    deriving (Storable, EndianStore, Equality, Eq)

  newtype Exchange X25519 = Exchange Word256
    deriving (Storable, EndianStore, Equality, Eq)

  newtype Secret X25519 = Secret Word256
    deriving (Storable, EndianStore, Equality, Eq)


instance Encodable (Private X25519)
instance Encodable (Exchange X25519)
instance Encodable (Secret X25519)

instance Show (Private X25519) where
  show = showBase16

instance Show (Exchange X25519) where
  show = showBase16

instance Show (Secret X25519) where
  show = showBase16
