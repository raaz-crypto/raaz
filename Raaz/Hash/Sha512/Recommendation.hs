-- | This sets up the recommended implementation of Sha512.
{-# OPTIONS_GHC -fno-warn-orphans #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Sha512.Recommendation where

import Raaz.Core
import Raaz.Hash.Sha512.Internal
import qualified Raaz.Hash.Sha512.Implementation.CPortable as CPortable

-- | Recommend implementation for SHA512.
instance Recommendation SHA512 where
  recommended _ = CPortable.implementation
