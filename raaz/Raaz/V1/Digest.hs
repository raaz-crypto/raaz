-- | The interface is the same as that of "Raaz.Digest" but the primitive
-- selection corresponds to the version 1 of the raaz library. Use
-- this module if you want compatibility with Version 1 of the
-- library.
--
-- For documentation refer to the module "Raaz.Digest".

module Raaz.V1.Digest
  (
    module Raaz.Digest.Blake2b
  , digestAlgorithm
  ) where

import Raaz.Core
import Raaz.Digest.Blake2b

-- | Algorithm used for message digest
digestAlgorithm :: String
digestAlgorithm = primName
