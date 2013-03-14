{-|

This module defines the hash instances for different hashes.

-}

{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha.Sha1.Instance () where

import Control.Applicative ((<$>))

import Raaz.Hash
import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha.Sha1.Type
import Raaz.Hash.Sha.Sha1.Ref.Sha1
import Raaz.Primitives
import Raaz.Types

instance BlockPrimitive SHA1 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}

  newtype Cxt SHA1 = SHA1Cxt SHA1

  processSingle (SHA1Cxt cxt) ptr = SHA1Cxt <$> sha1CompressSingle cxt ptr

instance HasPadding SHA1 where
  maxAdditionalBlocks _ = 1
  padLength = padLength64
  padding   = padding64

instance Hash SHA1 where
  startHashCxt = SHA1Cxt $ SHA1 0x67452301
                                0xefcdab89
                                0x98badcfe
                                0x10325476
                                0xc3d2e1f0
  finaliseHash (SHA1Cxt h) = h
