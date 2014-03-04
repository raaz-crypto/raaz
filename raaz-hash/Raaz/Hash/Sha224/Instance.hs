{-|

This module defines the hash instances for sha224 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha224.Instance () where

import Control.Applicative ( (<$>) )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash


import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Instance
import Raaz.Hash.Sha224.CPortable ()


----------------------------- SHA224 -------------------------------------------

instance CryptoPrimitive SHA224 where
  type Recommended SHA224 = CGadget SHA224
  type Reference SHA224   = HGadget SHA224

instance Hash SHA224

instance Gadget (HGadget SHA224) where
  type PrimitiveOf (HGadget SHA224) = SHA224
  type MemoryOf (HGadget SHA224) = CryptoCell SHA256
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA224IV sha1) = cellStore cc sha1
  finalize (HGadget cc) = sha256Tosha224 <$> cellLoad cc
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
  apply (HGadget cc) n cptr = sha256Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)
