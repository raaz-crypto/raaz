-- | This sets up the recommended implementation of Sha256.
{-# OPTIONS_GHC -fno-warn-orphans #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Sha256.Recommendation where

import Raaz.Core
import Raaz.Hash.Sha256.Internal
import qualified Raaz.Hash.Sha256.Implementation.CPortable as CPortable

instance Recommendation SHA256 where
  recommended _ = CPortable.implementation
