-- | The interface is the same as that of "Raaz.Digest" but the primitive
-- selection corresponds to the version 1 of the raaz library. Use
-- this module if you want compatibility with Version 1 of the
-- library.
--
-- For documentation refer to the module "Raaz.Digest".

module Raaz.V1.Digest ( Digest
                      , module Digest.Blake2b
                      ) where

import Digest.Blake2b
import Raaz.Primitive.Blake2.Internal(Blake2b)
type Digest = Blake2b
