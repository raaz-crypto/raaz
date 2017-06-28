-- | This sets up the recommended implementation of Sha1.
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Hash.Blake2.Recommendation where

import Raaz.Core
import Raaz.Hash.Blake2.Internal
import qualified Raaz.Hash.Blake2.Implementation.CPortable as CPortable


instance Recommendation BLAKE2b where
  recommended _ = CPortable.implementation2b


instance Recommendation BLAKE2s where
  recommended _ = CPortable.implementation2s
