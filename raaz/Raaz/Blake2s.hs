-- | This module exposes the interface to compute message digests
-- using the blake2s cryptographic hash.
module Raaz.Blake2s
       ( Blake2s
       , digest
       , digestFile
       , digestSource
       ) where

import qualified Blake2s.Interface as U
import           Raaz.Core
import           Raaz.Primitive.Blake2.Internal ( Blake2s )


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

