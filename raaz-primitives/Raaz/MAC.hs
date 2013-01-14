{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE FlexibleContexts #-}
module Raaz.MAC
       ( CryptoMAC(..)
       ) where

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
      , Eq          (MAC m)
      , CryptoStore (MAC m)
      ) => CryptoMAC m where

  -- | The MAC value.
  data MAC m       :: *

  -- | The secret key
  type MACSecret m :: *

  -- | Load the MAC secret from a crypto buffer.
  loadMACSecret    :: m                -- The mac algorithm
                   -> CryptoPtr        -- The cryptographic buffer
                   -> BYTES Int        -- The length of the secret
                   -> IO (MACSecret m)

  -- | The starting MAC context
  startMACCxt   :: m -> MACSecret m -> Cxt m

  -- | Finalise the context to a MAC value.
  finaliseMAC   :: m -> MACSecret m -> Cxt m -> MAC m
