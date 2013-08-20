{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.Primitives.MAC
       ( MACGadget(..), MAC
       , sourceMAC', sourceMAC
       , mac, mac'
       , macFile', macFile
       ) where
import qualified Data.ByteString as B
import           Prelude hiding (length)
import           System.IO(withBinaryFile, IOMode(ReadMode))
import           System.IO.Unsafe(unsafePerformIO)

import Raaz.Memory
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

class ( Gadget g
      , HasPadding (PrimitiveOf g)
      , Eq (PrimitiveOf g)
      , CryptoStore (PrimitiveOf g)
      ) => MACGadget g where

  -- | Convert a bytestring to a IV
  fromMACSecret  :: g -> B.ByteString -> IV (PrimitiveOf g)

class (CryptoPrimitive m, MACGadget (Recommended m)) => MAC m where

--------------------- Computing the MAC --------------------------------

-- | Compute the MAC of a given byte source with a given
-- implementation.
sourceMAC' :: ( MACGadget g
              , ByteSource src
              )
           => g
           -> B.ByteString -- ^ the secret
           -> src          -- ^ the message
           -> IO (PrimitiveOf g)
sourceMAC' g secret src = do
  init <- initializeMAC g
  transformGadget init src
  out <- finalize g
  freeGadget g
  return out
   where initializeMAC :: MACGadget g => g -> IO g
         initializeMAC g' = initialize (fromMACSecret g' secret) =<< newMemory
{-# INLINEABLE sourceMAC' #-}

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
mac' :: ( MACGadget g
        , PureByteSource src
        )
        => g
        -> B.ByteString -- ^ The secret
        -> src -- ^ The message
        -> PrimitiveOf g
mac' g secret = unsafePerformIO . sourceMAC' g secret

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
macFile' :: MACGadget g
         => g
         -> B.ByteString -- ^ the secret
         -> FilePath     -- ^ the input file
         -> IO (PrimitiveOf g)
macFile' g secret fp = withBinaryFile fp ReadMode $ sourceMAC' g secret

-- | Compute the MAC of a file with recommended implementation.
macFile :: MAC m
        => B.ByteString -- ^ the secret
        -> FilePath     -- ^ the input file
        -> IO m
macFile secret fp = withBinaryFile fp ReadMode $ sourceMAC secret
