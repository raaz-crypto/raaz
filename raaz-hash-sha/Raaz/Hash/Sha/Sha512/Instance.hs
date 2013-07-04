{-|

This module defines the hash instances for sha384 and sha512.

-}

{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha.Sha512.Instance (ReferenceSHA384, ReferenceSHA512) where

import Control.Applicative ((<$>))

import Raaz.Hash
import Raaz.Hash.Sha.Sha512.Type
import Raaz.Hash.Sha.Sha512.Ref.Sha512
import Raaz.Hash.Sha.Util
import Raaz.Primitives
import Raaz.Types

----------------------------- SHA384 -------------------------------------------

instance Primitive SHA384 where
  blockSize _ = cryptoCoerce $ BITS (1024 :: Int)
  {-# INLINE blockSize #-}

instance HasPadding SHA384 where
  maxAdditionalBlocks _ = 1
  padLength = padLength128
  padding   = padding128

instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = ReferenceSHA384

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

----------------------------- SHA512 -------------------------------------------

instance Primitive SHA512 where
  blockSize _ = cryptoCoerce $ BITS (1024 :: Int)
  {-# INLINE blockSize #-}

instance HasPadding SHA512 where
  maxAdditionalBlocks _ = 1
  padLength = padLength128
  padding   = padding128

instance CryptoPrimitive SHA512 where
  type Recommended SHA512 = ReferenceSHA512

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
