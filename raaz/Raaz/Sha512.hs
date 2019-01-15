-- | This module exposes the interface to compute message digests
-- using the sha512 cryptographic hash.
module Raaz.Sha512
       ( digest
       , digestFile
       , digestSource
       ) where

import           Raaz.Core
import           Raaz.Primitive.Sha2.Internal ( Sha512 )
import qualified Raaz.Sha512.Interface as U

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src              -- ^ Message
       -> Sha512
digest = U.digest

-- | Compute the digest of file.
digestFile :: FilePath     -- ^ File to be digested
           -> IO Sha512
digestFile = U.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src        -- ^ The source whose digest needs to be
                           -- computed.
             -> IO Sha512
digestSource = U.digestSource
