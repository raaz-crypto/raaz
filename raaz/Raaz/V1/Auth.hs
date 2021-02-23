-- | The interface is the same as that of "Raaz.Auth" but the
-- primitive selection corresponds to the version 1 of the raaz
-- library. Use this module if you want compatibility with Version 1
-- of the library.
--
-- For documentation refer the module "Raaz.Auth".

module Raaz.V1.Auth ( module Raaz.Auth.Blake2b
                    ) where
import Raaz.Auth.Blake2b
