-- | The interface is the same as that of "Raaz" but the primitive
-- selection corresponds to the version 1 of the raaz library. Use
-- this module if you want compatibility with Version 1 of the
-- library.
--
-- For documentation refer the top-most module "Raaz".

module Raaz.V1 ( module Raaz.V1.Digest
               , module Raaz.V1.Auth
               ) where

import Raaz.V1.Digest
import Raaz.V1.Auth
