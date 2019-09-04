-- | The interface is the same as that of "Raaz.Auth" but the
-- primitive selection corresponds to the version 1 of the raaz
-- library. Use this module if you want compatibility with Version 1
-- of the library.
--
-- For documentation refer the module "Raaz.Auth".

module Raaz.V1.Auth ( Auth
                    , auth, authFile, authSource
                    ) where

import           Raaz.Core
import qualified Raaz.Auth.Blake2b as B2bAuth
import           Raaz.Primitive.Blake2.Internal(Blake2b)
import           Raaz.Primitive.Keyed.Internal(Keyed)

-- | The message authentication.
type Auth   = Keyed Blake2b

-- | Compute the authenticator of a pure byte source like,
-- `B.ByteString`.
auth :: PureByteSource src
     => Key Auth
     -> src  -- ^ Message
     -> Auth
auth = B2bAuth.auth


-- | Compute the auth of file.
authFile :: Key Auth
         -> FilePath  -- ^ File to be authed
         -> IO Auth
authFile = B2bAuth.authFile

-- | Compute the auth of an arbitrary byte source.
authSource :: ByteSource src
           => Key Auth
           -> src
           -> IO Auth
authSource = B2bAuth.authSource
