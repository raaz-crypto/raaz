{-# LANGUAGE RecordWildCards       #-}
module Interface ( Auth
                 , auth
                 , authFile
                 , authSource
                 , AuthCxt
                 , startAuth
                 , updateAuth
                 , finaliseAuth
                 , name
                 , description
                 ) where

import GHC.TypeLits

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import qualified Implementation
import           Utils
import           Context

type Auth    = Implementation.Prim
type AuthCxt = Cxt
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

-- | Prepare the context to (re)start a session of incremental
-- processing.
startAuth :: KnownNat n
          => Key Auth   -- ^ The key to be used
          -> AuthCxt n
          -> IO ()
startAuth k cxt@Cxt{..} = do initialise k cxtInternals
                             unsafeSetCxtEmpty cxt


-- | Add some more data into the context, in this case the entirety of
-- the byte source src.
updateAuth :: (KnownNat n, ByteSource src)
           => src
           -> AuthCxt n
           -> IO ()
updateAuth = updateCxt

-- | Finalise the context to get hold of the digest.
finaliseAuth :: KnownNat n
             => AuthCxt n
             -> IO Auth
finaliseAuth cxt@Cxt{..} = finaliseCxt cxt >> extract cxtInternals


-- | Textual name of the authenticator implementation.
name :: String
name = Implementation.name

-- | Description of the implementation
description :: String
description = Implementation.description
