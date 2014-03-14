{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable () where

import Control.Applicative ( (<$>) )

import Raaz.Memory
import Raaz.Primitives

import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Type      ( SHA256(..) )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

instance Gadget (CGadget SHA224) where
  type PrimitiveOf (CGadget SHA224) = SHA224
  type MemoryOf (CGadget SHA224) = CryptoCell SHA256
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA224Cxt sha) = cellStore cc sha
  finalize (CGadget cc) = SHA224Cxt <$> cellLoad cc
  apply (CGadget cc) n cptr = sha256Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)

instance PaddableGadget (CGadget SHA224)
