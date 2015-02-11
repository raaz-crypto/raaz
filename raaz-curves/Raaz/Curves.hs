{-|

This module exposes all the cryptographic curves available
under the raaz library.

-}

module Raaz.Curves
       ( module Raaz.Curves.EC25519
       , module Raaz.Curves.ED25519
       ) where

import Raaz.Curves.EC25519
import Raaz.Curves.ED25519

{-# ANN module "HLint: ignore Use import/export shortcut" #-}
