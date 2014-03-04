{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable () where

import Raaz.Memory
import Raaz.Primitives

import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Type      ( SHA256(..) )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

instance Gadget (CGadget SHA224) where
  type PrimitiveOf (CGadget SHA224) = SHA224
  type MemoryOf (CGadget SHA224) = CryptoCell SHA256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA224IV sha) = cellStore cc sha
  finalize (CGadget cc) = sha256Tosha224 `fmap` cellLoad cc
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
  apply (CGadget cc) n cptr = sha256Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)
