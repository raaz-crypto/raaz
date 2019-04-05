-- | This module exposes the interface to compute message digests and
-- message authenticators using the blake2s cryptographic hash.
module Raaz.Blake2s
       ( -- * Message digest
         Blake2s
       , digest
       , digestFile
       , digestSource

         -- * Message authenticator
       , auth
       , authFile
       , authSource

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

-- | Using the keyed hashing for blake2s compute the message
-- authenticator.
auth :: PureByteSource src
     => Key (Keyed Blake2s)
     -> src  -- ^ Message
     -> Keyed Blake2s
auth  = A.auth

-- | Compute the message authenticator for a file.
authFile :: Key (Keyed Blake2s)
         -> FilePath  -- ^ File to be authed
         -> IO (Keyed Blake2s)
authFile = A.authFile

-- | Compute the message authenticator for an arbitrary byte source.
authSource :: ByteSource src
           => Key (Keyed Blake2s)
           -> src
           -> IO (Keyed Blake2s)

authSource = A.authSource
