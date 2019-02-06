module Interface ( auth
                 , authFile
                 , authSource
                 , verify
                 , verifyFile
                 , verifySource
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
{-# INLINEABLE verify #-}
{-# SPECIALIZE auth :: Key Prim -> B.ByteString -> Prim #-}
{-# SPECIALIZE auth :: Key Prim -> L.ByteString -> Prim #-}

-- | Verify a message using the authentication tag.
verify :: PureByteSource src
       => Key Prim            -- ^ The secret key used.
       -> Prim                -- ^ The authentication tag.
       -> src                 -- ^ Message to authenticate.
       -> Bool
verify key tag src = auth key src == tag
  -- The equality checking by design timing safe so do not worry.

-- | Compute the auth of file.
authFile :: Key Prim
         -> FilePath  -- ^ File to be authed
         -> IO Prim
authFile key fileName = withBinaryFile fileName ReadMode $ authSource key
{-# INLINEABLE authFile   #-}
{-# INLINEABLE verifyFile #-}
-- | Verify
verifyFile :: Key Prim
           -> Prim
           -> FilePath
           -> IO Bool
verifyFile key tag = fmap (==tag) . authFile key

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

verifySource :: ByteSource src
             => Key Prim
             -> Prim
             -> src
             -> IO Bool
verifySource key tag  = fmap (==tag) . authSource key
