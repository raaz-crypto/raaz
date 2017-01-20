-- | This sets up the recommended implementation of chacha20 cipher.

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE CPP                  #-}

--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Cipher.ChaCha20.Recommendation
       ( RandomBlock, chacha20Random
       ) where

import Raaz.Core
import Raaz.Cipher.ChaCha20.Internal

#ifdef HAVE_VECTOR_256
import Raaz.Cipher.ChaCha20.Implementation.Vector256
#else
import Raaz.Cipher.ChaCha20.Implementation.CPortable
#endif

instance Recommendation ChaCha20 where
         recommended _ = implementation
