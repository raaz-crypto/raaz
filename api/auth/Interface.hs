module Interface ( Auth
                 , auth
                 , authFile
                 , authSource
                 , name
                 , description
                 ) where

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import qualified Implementation
import           Utils

type Auth = Implementation.Prim

-- | Compute the authenticator of a pure byte source like,
-- `B.ByteString`.
auth :: PureByteSource src
     => Key Auth
     -> src  -- ^ Message
     -> Auth
auth key = unsafePerformIO . authSource key
{-# INLINEABLE auth #-}
{-# SPECIALIZE auth :: Key Auth -> B.ByteString -> Auth #-}
{-# SPECIALIZE auth :: Key Auth -> L.ByteString -> Auth #-}

-- | Compute the auth of file.
authFile :: Key Auth
         -> FilePath  -- ^ File to be authed
         -> IO Auth
authFile key fileName = withBinaryFile fileName ReadMode $ authSource key
{-# INLINEABLE authFile   #-}


-- | Compute the auth of an arbitrary byte source.
authSource :: ByteSource src
           => Key Auth
           -> src
           -> IO Auth
{-# SPECIALIZE authSource :: Key Auth -> B.ByteString -> IO Auth #-}
{-# SPECIALIZE authSource :: Key Auth -> L.ByteString -> IO Auth #-}
{-# SPECIALIZE authSource :: Key Auth -> Handle       -> IO Auth #-}

authSource key src = withMemory $ \ mem -> do
  initialise key mem
  processByteSource src mem
  extract mem


-- | Textual name of the authenticator implementation.
name :: String
name = Implementation.name

-- | Description of the implementation
description :: String
description = Implementation.description
