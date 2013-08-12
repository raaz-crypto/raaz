{-|

This module defines the hash instances for sha256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE EmptyDataDecls       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha256.Instance (ReferenceSHA256) where

import Control.Applicative ((<$>))

import Raaz.Primitives
import Raaz.Primitives.Hash


import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha256.CPortable


----------------------------- SHA256 -------------------------------------------

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = CPortable

instance Hash SHA256 where

-- | Reference Implementation
data ReferenceSHA256

instance Implementation ReferenceSHA256 where
  type PrimitiveOf ReferenceSHA256 = SHA256
  newtype Cxt ReferenceSHA256 = SHA256Cxt SHA256
  processSingle (SHA256Cxt cxt) ptr = SHA256Cxt <$> sha256CompressSingle cxt ptr

instance HashImplementation ReferenceSHA256 where
  startHashCxt = SHA256Cxt $ SHA256 0x6a09e667
                                    0xbb67ae85
                                    0x3c6ef372
                                    0xa54ff53a
                                    0x510e527f
                                    0x9b05688c
                                    0x1f83d9ab
                                    0x5be0cd19
  finaliseHash (SHA256Cxt h) = h
