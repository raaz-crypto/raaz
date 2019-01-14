-- | This module exposes the interface to compute message digests
-- using the sha256 cryptographic hash.
module Raaz.Sha256
       ( digest
       , digestFile
       , digestSource
       ) where

import           Raaz.Core
import           Raaz.Primitive.Sha2.Internal ( Sha256 )
import qualified Raaz.Sha256.Utils as U

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src              -- ^ Message
       -> Sha256
digest = U.digest

-- | Compute the digest of file.
digestFile :: FilePath     -- ^ File to be digested
           -> IO Sha256
digestFile = U.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src        -- ^ The source whose digest needs to be
                           -- computed.
             -> IO Sha256
digestSource = U.digestSource

