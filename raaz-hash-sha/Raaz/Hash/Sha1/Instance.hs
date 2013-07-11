{-|

This module defines the hash instances for different hashes.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE EmptyDataDecls       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha1.Instance (ReferenceSHA1) where

import Control.Applicative ((<$>))

import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha1.Type
import Raaz.Hash.Sha1.Ref

----------------------------- SHA1 ---------------------------------------------

instance CryptoPrimitive SHA1 where
  type Recommended SHA1 = ReferenceSHA1

instance Hash SHA1 where

-- | Reference Implementation
data ReferenceSHA1

instance Implementation ReferenceSHA1 where
  type PrimitiveOf ReferenceSHA1 = SHA1
  newtype Cxt ReferenceSHA1 = SHA1Cxt SHA1
  processSingle (SHA1Cxt cxt) ptr = SHA1Cxt <$> sha1CompressSingle cxt ptr

instance HashImplementation ReferenceSHA1 where
  startHashCxt = SHA1Cxt $ SHA1 0x67452301
                                0xefcdab89
                                0x98badcfe
                                0x10325476
                                0xc3d2e1f0
  finaliseHash (SHA1Cxt h) = h
