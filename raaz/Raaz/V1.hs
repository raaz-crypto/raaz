{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Version 1 of the interface.
module Raaz.V1 ( Digest
               -- For digests and message authentication.
               , module Raaz.Blake2b
               ) where

import           Raaz.Blake2b

type Digest = Blake2b
