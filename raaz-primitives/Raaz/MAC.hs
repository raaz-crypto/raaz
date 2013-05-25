{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.MAC
       ( MACImplementation(..), MAC
       , mac', mac
       , macByteString', macByteString
       , macLazyByteString', macLazyByteString
       , macFile', macFile
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

class ( BlockImplementation i m
      , HasPadding  m
      , Eq          m
      , CryptoStore m
      ) => MACImplementation i m where

  -- | The secret key
  data MACSecret i m :: *

  -- | Convert a bytestring to a secret
  toMACSecret  :: B.ByteString -> MACSecret i m

  -- | The starting MAC context
  startMACCxt  :: MACSecret i m -> Cxt i m

  -- | Finalise the context to a MAC value.
  finaliseMAC  :: MACSecret i m -> Cxt i m -> m

class MACImplementation (DefaultBlockImplementation m) m => MAC m where

-- | Compute the MAC for the byte source.
mac' :: ( ByteSource src
        , MACImplementation i m
        )
    => i              -- ^ Implementation
    -> B.ByteString   -- ^ the secret
    -> src            -- ^ the input byte source
    -> IO m
mac' i secret src =   transformContext cxt0 src
                  >>= return . finaliseMAC (macsecret i)
    where macsecret :: MACImplementation i m => i -> MACSecret i m
          macsecret _ = toMACSecret secret
          cxt0      = startMACCxt (macsecret i)


mac :: ( ByteSource src, MAC m)
    => B.ByteString
    -> src
    -> IO m
mac secret src = go undefined undefined
  where go :: MAC m => m -> DefaultBlockImplementation m -> IO m
        go _ i = mac' i secret src

-- | Compute the MAC of a strict bytestring.
macByteString' :: MACImplementation i m
               => i            -- ^ Implementation
               -> B.ByteString -- ^ the secret
               -> B.ByteString -- ^ the input strict bytestring
               -> m
macByteString' i secret = unsafePerformIO . mac' i secret

macByteString :: MAC m
              => B.ByteString -- ^ the secret
              -> B.ByteString -- ^ the input strict bytestring
              -> m
macByteString secret = unsafePerformIO . mac secret

-- | Compute the MAC of a lazy bytestring
macLazyByteString' :: MACImplementation i m
                   => i            -- ^ Implementation
                   -> B.ByteString -- ^ the secret
                   -> L.ByteString -- ^ the input lazy bytestring
                   -> m
macLazyByteString' i secret = unsafePerformIO . mac' i secret

macLazyByteString :: MAC m
                  => B.ByteString -- ^ the secret
                  -> L.ByteString -- ^ the input lazy bytestring
                  -> m
macLazyByteString secret = unsafePerformIO . mac secret

-- | Compute the MAC of a file.
macFile' :: MACImplementation i m
         => i            -- ^ Implementation
         -> B.ByteString -- ^ the secret
         -> FilePath     -- ^ the input file
         -> IO m
macFile' i secret fp =  transformContextFile cxt0 fp
                  >>= return . finaliseMAC (macsecret i)
    where macsecret :: MACImplementation i m => i -> MACSecret i m
          macsecret _ = toMACSecret secret
          cxt0      = startMACCxt (macsecret i)

macFile :: MAC m
        => B.ByteString -- ^ the secret
        -> FilePath     -- ^ the input file
        -> IO m
macFile bs fp = go undefined undefined
  where go :: MAC m => m -> DefaultBlockImplementation m -> IO m
        go _ i = macFile' i bs fp
