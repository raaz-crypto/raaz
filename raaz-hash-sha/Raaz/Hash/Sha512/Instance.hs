{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha512.Instance (ReferenceSHA512) where

import Control.Applicative ((<$>))

import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha512.Type
import Raaz.Hash.Sha512.Ref
import Raaz.Hash.Sha512.CPortable


----------------------------- SHA512 -------------------------------------------


instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = CPortable

instance Hash SHA512 where

-- | Reference Implementation
data ReferenceSHA512

instance Implementation ReferenceSHA512 where
  type PrimitiveOf ReferenceSHA512 = SHA512
  newtype Cxt ReferenceSHA512 = SHA512Cxt SHA512
  processSingle (SHA512Cxt cxt) ptr = SHA512Cxt <$> sha512CompressSingle cxt ptr

instance HashImplementation ReferenceSHA512 where
  startHashCxt = SHA512Cxt $ SHA512 0x6a09e667f3bcc908
                                    0xbb67ae8584caa73b
                                    0x3c6ef372fe94f82b
                                    0xa54ff53a5f1d36f1
                                    0x510e527fade682d1
                                    0x9b05688c2b3e6c1f
                                    0x1f83d9abfb41bd6b
                                    0x5be0cd19137e2179
  finaliseHash (SHA512Cxt h) = h
