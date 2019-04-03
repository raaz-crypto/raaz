-- | This module exposes the interface to compute message digests and
-- message authenticators using the blake2b cryptographic hash.
module Raaz.Blake2b
       ( -- * Message digest
         Blake2b
       , digest
       , digestFile
       , digestSource
         -- * Message authenticator
       , auth
       , authFile
       , authSource
       ) where

import qualified Blake2b.Interface as U
import qualified Blake2b.Mac.Interface as A
import           Raaz.Core
import           Raaz.Primitive.Blake2.Internal ( Blake2b )
import           Raaz.Primitive.Keyed.Internal  (Keyed, HashKey)


-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src              -- ^ Message
       -> Blake2b
digest = U.digest

-- | Compute the digest of file.
digestFile :: FilePath     -- ^ File to be digested
           -> IO Blake2b
digestFile = U.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src        -- ^ The source whose digest needs to be
                           -- computed.
             -> IO Blake2b
digestSource = U.digestSource

-- | Using the keyed hashing for blake2s compute the message
-- authenticator.
auth :: PureByteSource src
     => HashKey Blake2b
     -> src  -- ^ Message
     -> Keyed Blake2b
auth  = A.auth

-- | Compute the message authenticator for a file.
authFile :: HashKey Blake2b
         -> FilePath  -- ^ File to be authed
         -> IO (Keyed Blake2b)
authFile = A.authFile

-- | Compute the message authenticator for an arbitrary byte source.
authSource :: ByteSource src
           => HashKey Blake2b
           -> src
           -> IO (Keyed Blake2b)

authSource = A.authSource
