-- | This module exposes the interface to compute message digests
-- using the blake2s cryptographic hash.
module Raaz.Blake2s
       ( Blake2s
       , digest
       , digestFile
       , digestSource
       , auth, verify
       , authFile, verifyFile
       , authSource, verifySource

       ) where

import qualified Blake2s.Interface as U
import qualified Blake2s.Mac.Interface as A
import           Raaz.Core
import           Raaz.Primitive.Blake2.Internal ( Blake2s )
import           Raaz.Primitive.Keyed.Internal  (Keyed)

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src              -- ^ Message
       -> Blake2s
digest = U.digest

-- | Compute the digest of file.
digestFile :: FilePath     -- ^ File to be digested
           -> IO Blake2s
digestFile = U.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src        -- ^ The source whose digest needs to be
                           -- computed.
             -> IO Blake2s
digestSource = U.digestSource

-- | Use the blake2b hashing algorithm as a message authenticator
-- using the keyed hashing algorithm for blake2b.
auth :: PureByteSource src
     => Key (Keyed Blake2s)
     -> src  -- ^ Message
     -> Keyed Blake2s
auth  = A.auth

-- | Verify a message using the authentication tag.
verify :: PureByteSource src
       => Key (Keyed Blake2s) -- ^ The secret key used.
       -> Keyed Blake2s       -- ^ The authentication tag.
       -> src                 -- ^ Message to authenticate.
       -> Bool
verify = A.verify
  -- The equality checking by design timing safe so do not worry.

-- | Compute the auth of file.
authFile :: Key (Keyed Blake2s)
         -> FilePath  -- ^ File to be authed
         -> IO (Keyed Blake2s)
authFile = A.authFile

-- | Verify
verifyFile :: Key (Keyed Blake2s)
           -> Keyed Blake2s
           -> FilePath
           -> IO Bool
verifyFile = A.verifyFile

-- | Compute the auth of an arbitrary byte source.
authSource :: ByteSource src
           => Key (Keyed Blake2s)
           -> src
           -> IO (Keyed Blake2s)

authSource = A.authSource

verifySource :: ByteSource src
             => Key (Keyed Blake2s)
             -> Keyed Blake2s
             -> src
             -> IO Bool
verifySource = A.verifySource
