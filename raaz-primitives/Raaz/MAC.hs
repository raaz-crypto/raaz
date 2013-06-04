{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.MAC
       ( MACImplementation(..), MAC(..)
       , sourceMAC', sourceMAC
       , mac, mac'
       , macFile', macFile
       ) where
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding (length)
import           System.IO(withBinaryFile, IOMode(ReadMode))
import           System.IO.Unsafe(unsafePerformIO)

import Raaz.Types
import Raaz.ByteSource
import Raaz.Primitives

-- | The class captures implementation of cryptographic message
-- authentication primitives.
--
-- [Warning] While defining the @'Eq'@ instance of @'MAC' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
--

class ( Implementation i
      , HasPadding (PrimitiveOf i)
      , Eq (PrimitiveOf i)
      , CryptoStore (PrimitiveOf i)
      ) => MACImplementation i where

  -- | The secret key
  data MACSecret i :: *

  -- | Convert a bytestring to a secret
  toMACSecret  :: B.ByteString -> MACSecret i

  -- | The starting MAC context
  startMACCxt  :: MACSecret i -> Cxt i

  -- | Finalise the context to a MAC value.
  finaliseMAC  :: MACSecret i -> Cxt i -> PrimitiveOf i

class (CryptoPrimitive m, MACImplementation (Recommended m)) => MAC m where

--------------------- Computing the MAC --------------------------------

-- | Compute the MAC of a given byte source with a given
-- implementation.
sourceMAC' :: ( MACImplementation i
              , ByteSource src
              )
           => i
           -> B.ByteString -- ^ the secret
           -> src          -- ^ the message
           -> IO (PrimitiveOf i)
sourceMAC' i secret src =   transformContext cxt0 src
                        >>= return . finaliseMAC macsecret
  where getSecret :: MACImplementation i => i -> MACSecret i
        getSecret _ = toMACSecret secret
        macsecret   = getSecret i
        cxt0        = startMACCxt macsecret

-- | Compute the MAC for the byte source using the recomended
-- implementation.
sourceMAC :: ( ByteSource src
             , MAC m
             )
          => B.ByteString   -- ^ the secret
          -> src            -- ^ the message
          -> IO m
sourceMAC secret src = go undefined
  where go :: MAC m => Recommended m -> IO m
        go i = sourceMAC' i secret src

--------------------- MAC for pure source ------------------------------

-- | Compute the MAC of a pure byte source.
-- LazyByteString etc.
mac' :: ( MACImplementation i
        , PureByteSource src
        )
        => i
        -> B.ByteString -- ^ The secret
        -> src -- ^ The message
        -> PrimitiveOf i
mac' i secret = unsafePerformIO . sourceMAC' i secret

-- | Compute the MAC of a pure byte source.
mac :: ( MAC m
       , PureByteSource src
       )
    => B.ByteString -- ^ the secret
    -> src          -- ^ the message
    -> m
mac secret = unsafePerformIO . sourceMAC secret

----------------------- MACing a file ----------------------------------

-- | Compute the MAC of a file.
macFile' :: MACImplementation i
         => i
         -> B.ByteString -- ^ the secret
         -> FilePath     -- ^ the input file
         -> IO (PrimitiveOf i)
macFile' i secret fp = withBinaryFile fp ReadMode $ sourceMAC' i secret

-- | Compute the MAC of a file with recommended implementation.
macFile :: MAC m
        => B.ByteString -- ^ the secret
        -> FilePath     -- ^ the input file
        -> IO m
macFile secret fp = withBinaryFile fp ReadMode $ sourceMAC secret
