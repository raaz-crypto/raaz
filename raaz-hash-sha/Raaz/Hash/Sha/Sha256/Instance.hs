{-|

This module defines the hash instances for sha224 and sha256 hashes.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE EmptyDataDecls       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha.Sha256.Instance (ReferenceSHA224, ReferenceSHA256) where

import Control.Applicative ((<$>))

import Raaz.Hash
import Raaz.Hash.Sha.Sha256.Type
import Raaz.Hash.Sha.Sha256.Ref.Sha256
import Raaz.Hash.Sha.Util
import Raaz.Primitives
import Raaz.Types

----------------------------- SHA224 -------------------------------------------

instance Primitive SHA224 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}

instance HasPadding SHA224 where
  maxAdditionalBlocks _ = 1
  padLength = padLength64
  padding   = padding64

instance CryptoPrimitive SHA224 where
  type Recommended SHA224 = ReferenceSHA224

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

----------------------------- SHA256 -------------------------------------------

instance Primitive SHA256 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}

instance HasPadding SHA256 where
  maxAdditionalBlocks _ = 1
  padLength = padLength64
  padding   = padding64

instance CryptoPrimitive SHA256 where
  type Recommended SHA256 = ReferenceSHA256

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
