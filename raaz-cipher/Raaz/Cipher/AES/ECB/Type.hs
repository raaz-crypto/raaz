{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.ECB.Type where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types

import Raaz.Cipher.AES.Internal


instance Primitive (AES ECB k) where
  blockSize _          = BYTES 16
  {-# INLINE blockSize #-}
  type Cxt (AES ECB k) = k

instance Cipher (AES ECB k) where
  cipherCxt _ = id

type instance Key (AES ECB k) = k
