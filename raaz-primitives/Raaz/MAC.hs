{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE FlexibleContexts #-}
module Raaz.MAC
       ( MAC(..)
       ) where
import Data.ByteString(ByteString)

import Raaz.Types
import Raaz.Primitives

-- | The class that captures a cryptographic message authentication
-- algorithm. The associated type @MAC m@ captures the actual MAC
-- value.
--
-- [Warning] While defining the @'Eq'@ instance of @'MAC' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
--

class ( BlockPrimitive m
      , HasPadding  m
      , Eq          m
      , CryptoStore m
      ) => MAC m where

  -- | The secret key
  data MACSecret m :: *

  -- | Convert a bytestring to a secret
  toMACSecret  :: ByteString -> MACSecret m

  -- | The starting MAC context
  startMAC     :: MACSecret m -> Cxt m

  -- | Finalise the context to a MAC value.
  finaliseMAC  :: MACSecret m -> Cxt m -> m
