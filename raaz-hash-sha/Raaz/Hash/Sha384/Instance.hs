{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance (ReferenceSHA384) where

import Control.Applicative ((<$>))

import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha384.CPortable


----------------------------- SHA384 -------------------------------------------


instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = CPortable

instance Hash SHA384 where

-- | Reference Implementation
data ReferenceSHA384

instance Implementation ReferenceSHA384 where
  type PrimitiveOf ReferenceSHA384 = SHA384
  newtype Cxt ReferenceSHA384 = SHA384Cxt SHA512
  processSingle (SHA384Cxt cxt) ptr = SHA384Cxt <$> sha512CompressSingle cxt ptr

instance HashImplementation ReferenceSHA384 where
  startHashCxt = SHA384Cxt $ SHA512 0xcbbb9d5dc1059ed8
                                    0x629a292a367cd507
                                    0x9159015a3070dd17
                                    0x152fecd8f70e5939
                                    0x67332667ffc00b31
                                    0x8eb44a8768581511
                                    0xdb0c2e0d64f98fa7
                                    0x47b5481dbefa4fa4
  finaliseHash (SHA384Cxt h) = sha512Tosha384 h
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = (SHA384 h0 h1 h2 h3 h4 h5)
