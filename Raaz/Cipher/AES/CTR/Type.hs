{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Cipher.AES.Block.Internal
import Raaz.Cipher.AES.Internal


instance Primitive (AES CTR k) where
  blockSize _          = BYTES 1
  {-# INLINE blockSize #-}
  type Key (AES CTR k) = (k, STATE)

instance Cipher (AES CTR k)
