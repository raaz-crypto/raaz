-- | This sets up the recommended implementation of Sha224.
{-# OPTIONS_GHC -fno-warn-orphans #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Sha224.Recommendation where

import Raaz.Core
import Raaz.Hash.Sha224.Internal
import qualified Raaz.Hash.Sha224.Implementation.CPortable as CPortable

-- | Recommended implementation for SHA224.
instance Recommendation SHA224 where
  recommended _ = CPortable.implementation
