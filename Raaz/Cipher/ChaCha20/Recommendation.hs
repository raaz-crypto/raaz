-- | This sets up the recommended implementation of chacha20 cipher.

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Cipher.ChaCha20.Recommendation where

import           Raaz.Core
import           Raaz.Cipher.ChaCha20.Internal
import qualified Raaz.Cipher.ChaCha20.Implementation.CPortable as CP

instance Recommendation ChaCha20 where
         recommended _ = CP.implementation
