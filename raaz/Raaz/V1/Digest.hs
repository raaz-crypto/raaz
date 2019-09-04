-- | The interface is the same as that of "Raaz.Digest" but the primitive
-- selection corresponds to the version 1 of the raaz library. Use
-- this module if you want compatibility with Version 1 of the
-- library.
--
-- For documentation refer to the module "Raaz.Digest".

module Raaz.V1.Digest ( Digest
                      , digest
                      , digestFile
                      , digestSource
                      ) where

import qualified Raaz.Digest.Blake2b as B2b
import           Raaz.Core
import           Raaz.Primitive.Blake2.Internal(Blake2b)

-- | The message digest.
type Digest = Blake2b

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src  -- ^ Message
       -> Digest
digest = B2b.digest

-- | Compute the digest of file.
digestFile :: FilePath  -- ^ File to be digested
           -> IO Digest
digestFile = B2b.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src
             -> IO Digest
digestSource = B2b.digestSource
