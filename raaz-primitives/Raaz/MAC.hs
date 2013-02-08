{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.MAC
       ( MAC(..)
       , mac
       , macByteString, macLazyByteString
       , macFile
       ) where
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding (length)
import           System.IO.Unsafe(unsafePerformIO)

import Raaz.Types
import Raaz.ByteSource
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
  toMACSecret  :: m -> B.ByteString -> MACSecret m

  -- | The starting MAC context
  startMACCxt  :: MACSecret m -> Cxt m

  -- | Finalise the context to a MAC value.
  finaliseMAC  :: MACSecret m -> Cxt m -> m

-- | Compute the MAC for the byte source.
mac :: ( ByteSource src
       , MAC m
       )
    => B.ByteString   -- ^ the secret
    -> src            -- ^ the input byte source
    -> IO m

mac secret src =   transformContext cxt0 src
               >>= return . finaliseMAC macsecret
    where macsecret = toMACSecret undefined secret
          cxt0      = startMACCxt macsecret

-- | Compute the MAC of a strict bytestring.
macByteString :: MAC m
              => B.ByteString -- ^ the secret
              -> B.ByteString -- ^ the input strict bytestring
              -> m
macByteString secret = unsafePerformIO . mac secret

-- | Compute the MAC of a lazy bytestring
macLazyByteString :: MAC m
                  => B.ByteString -- ^ the secret
                  -> L.ByteString -- ^ the input lazy bytestring
                  -> m
macLazyByteString secret = unsafePerformIO . mac secret

-- | Compute the MAC of a file.
macFile :: MAC m
        => B.ByteString -- ^ the secret
        -> FilePath     -- ^ the input file
        -> IO m

macFile secret fp =   transformContextFile cxt0 fp
                   >>= return . finaliseMAC macsecret
    where macsecret = toMACSecret undefined secret
          cxt0      = startMACCxt macsecret
