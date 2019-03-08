module Interface ( auth
                 , authFile
                 , authSource
                 ) where

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import           Implementation
import           Utils

-- | Compute the authenticator of a pure byte source like,
-- `B.ByteString`.
auth :: PureByteSource src
     => Key Prim
     -> src  -- ^ Message
     -> Prim
auth key = unsafePerformIO . authSource key
{-# INLINEABLE auth #-}
{-# SPECIALIZE auth :: Key Prim -> B.ByteString -> Prim #-}
{-# SPECIALIZE auth :: Key Prim -> L.ByteString -> Prim #-}

-- | Compute the auth of file.
authFile :: Key Prim
         -> FilePath  -- ^ File to be authed
         -> IO Prim
authFile key fileName = withBinaryFile fileName ReadMode $ authSource key
{-# INLINEABLE authFile   #-}


-- | Compute the auth of an arbitrary byte source.
authSource :: ByteSource src
           => Key Prim
           -> src
           -> IO Prim
{-# SPECIALIZE authSource :: Key Prim -> B.ByteString -> IO Prim #-}
{-# SPECIALIZE authSource :: Key Prim -> L.ByteString -> IO Prim #-}
{-# SPECIALIZE authSource :: Key Prim -> Handle       -> IO Prim #-}

authSource key src = insecurely $ do
  initialise key
  processByteSource src
  extract
