{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.MAC
       ( MACImplementation(..)
       , mac', mac
       , macByteString', macByteString
       , macLazyByteString, macLazyByteString'
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

mac' :: ( MACImplementation i
        , ByteSource src
        )
     => i
     -> B.ByteString -- ^ the secret
     -> src
     -> IO (PrimitiveOf i)

mac' i secret src =   transformContext cxt0 src
                  >>= return . finaliseMAC macsecret
  where getSecret :: MACImplementation i => i -> MACSecret i
        getSecret _ = toMACSecret secret
        macsecret   = getSecret i
        cxt0        = startMACCxt macsecret

-- | Compute the MAC for the byte source.
mac :: ( ByteSource src
       , MAC m
       )
    => B.ByteString   -- ^ the secret
    -> src            -- ^ the input byte source
    -> IO m
mac secret src = go undefined
  where go :: MAC m => Recommended m -> IO m
        go i = mac' i secret src

------------------ Unsafe MACs (For internal use only) -----------------

-- | WARNING: Do not export. It is meant to be used only for pure
-- bytesources. Unsafe version of mac'. This is not exported by the
-- module and is only used for bytesources that are known to be pure.
unsafeMAC' :: ( MACImplementation i
              , ByteSource src
              )
           => i
           -> B.ByteString -- secret
           -> src
           -> PrimitiveOf i
unsafeMAC' i secret = unsafePerformIO . mac' i secret
{-# INLINE unsafeMAC' #-}

-- | Similar to unsafeMAC' but uses the recommended implementation.
unsafeMAC :: ( MAC m
             , ByteSource src
             )
          => B.ByteString -- secret
          -> src
          -> m
unsafeMAC secret = unsafePerformIO . mac secret
{-# INLINE unsafeMAC #-}

--------------------- MAC for Bytestring -------------------------------

macByteString' :: MACImplementation i
               => i
               -> B.ByteString -- ^ The secret
               -> B.ByteString -- ^ The message
               -> PrimitiveOf i
macByteString' = unsafeMAC'
-- | Compute the MAC of a strict bytestring.

macByteString :: MAC m
              => B.ByteString -- ^ the secret
              -> B.ByteString -- ^ the input strict bytestring
              -> m
macByteString = unsafeMAC


-- | Compute the MAC of a lazy bytestring
macLazyByteString' :: MACImplementation i
                   => i
                   -> B.ByteString -- ^ the secret
                   -> L.ByteString -- ^ the input lazy bytestring
                   -> PrimitiveOf i
macLazyByteString' = unsafeMAC'

-- | Compute the MAC of a lazy bytestring
macLazyByteString :: MAC m
                  => B.ByteString -- ^ the secret
                  -> L.ByteString -- ^ the input lazy bytestring
                  -> m
macLazyByteString = unsafeMAC

----------------------- MACing a file ----------------------------------

-- | Compute the MAC of a file.
macFile' :: MACImplementation i
         => i
         -> B.ByteString -- ^ the secret
         -> FilePath     -- ^ the input file
         -> IO (PrimitiveOf i)
macFile' i secret fp = withBinaryFile fp ReadMode $ mac' i secret

-- | Compute the MAC of a file with recommended implementation.
macFile :: MAC m
        => B.ByteString -- ^ the secret
        -> FilePath     -- ^ the input file
        -> IO m
macFile secret fp = withBinaryFile fp ReadMode $ mac secret
