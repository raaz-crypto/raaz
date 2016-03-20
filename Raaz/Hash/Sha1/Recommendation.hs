-- | This sets up the recommended implementation of Sha1.
{-# OPTIONS_GHC -fno-warn-orphans #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Sha1.Recommendation where

import Raaz.Core
import Raaz.Hash.Sha1.Internal
import qualified Raaz.Hash.Sha1.Implementation.CPortable as CPortable

instance Recommendation SHA1 where
  recommended _ = CPortable.implementation
