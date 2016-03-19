-- | This sets up the recommended implementation of Sha384.
{-# OPTIONS_GHC -fno-warn-orphans #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Sha384.Recommendation where

import Raaz.Core
import Raaz.Hash.Sha384.Internal
import qualified Raaz.Hash.Sha384.Implementation.CPortable as CPortable

instance Recommendation SHA384 where
  recommended _ = CPortable.implementation
