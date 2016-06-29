-- | This is the top-level module for the Raaz cryptographic library.
-- By importing this module you get a rather high-level access to the
-- primitives provided by the library.
module Raaz
       ( module Raaz.Cipher
       , module Raaz.Core
       , module Raaz.Hash
       , version
       ) where

import           Data.Version  (Version)
import qualified Paths_raaz as P

import           Raaz.Core
import           Raaz.Hash
import           Raaz.Cipher


-- | Raaz library version number.
version :: Version
version = P.version
