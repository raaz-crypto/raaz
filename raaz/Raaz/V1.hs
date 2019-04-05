{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | The interface is the same as that of "Raaz" but the primitive
-- selection corresponds to the version 1 of the raaz library. Use
-- this module if you want compatibility with Version 1 of the
-- library.
--
-- For documentation refer the top-most module "Raaz".

module Raaz.V1 ( Digest
               , Auth
               , module Raaz.Blake2b
               ) where

import Raaz.Blake2b
import Raaz.Primitive.Keyed.Internal(Keyed)

type Digest = Blake2b
type Auth   = Keyed Blake2b
