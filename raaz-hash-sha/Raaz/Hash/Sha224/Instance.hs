{-|

This module defines the hash instances for sha224 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE EmptyDataDecls       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha224.Instance (ReferenceSHA224) where

import Control.Applicative ((<$>))

import Raaz.Primitives
import Raaz.Primitives.Hash


import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Ref
import Raaz.Hash.Sha224.CPortable


----------------------------- SHA224 -------------------------------------------

instance CryptoPrimitive SHA224 where
  type Recommended SHA224 = CPortable


instance Hash SHA224 where

-- | Reference Implementation
data ReferenceSHA224

instance Implementation ReferenceSHA224 where
  type PrimitiveOf ReferenceSHA224 = SHA224
  newtype Cxt ReferenceSHA224 = SHA224Cxt SHA256
  processSingle (SHA224Cxt cxt) ptr = SHA224Cxt <$> sha256CompressSingle cxt ptr

instance HashImplementation ReferenceSHA224 where
  startHashCxt = SHA224Cxt $ SHA256 0xc1059ed8
                                    0x367cd507
                                    0x3070dd17
                                    0xf70e5939
                                    0xffc00b31
                                    0x68581511
                                    0x64f98fa7
                                    0xbefa4fa4

  finaliseHash (SHA224Cxt h) = sha256Tosha224 h
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
