{-|

This module defines the hash instances for sha384 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Sha384.Instance () where

import Control.Applicative ( (<$>) )

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type ( SHA512(..) )
import Raaz.Hash.Sha512.Instance
import Raaz.Hash.Sha384.CPortable ()


----------------------------- SHA384 -------------------------------------------

instance CryptoPrimitive SHA384 where
  type Recommended SHA384 = CGadget SHA384
  type Reference SHA384   = HGadget SHA384

instance Hash SHA384

instance Gadget (HGadget SHA384) where
  type PrimitiveOf (HGadget SHA384) = SHA384
  type MemoryOf (HGadget SHA384) = CryptoCell SHA512
  newGadgetWithMemory = return . HGadget
  initialize (HGadget cc) (SHA384IV sha1) = cellStore cc sha1
  finalize (HGadget cc) = sha512Tosha384 <$> cellLoad cc
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = SHA384 h0 h1 h2 h3 h4 h5
  apply (HGadget cc) n cptr = sha512Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)
