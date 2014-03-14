{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Hash.Sha384.CPortable () where

import Control.Applicative ((<$>))

import Raaz.Memory
import Raaz.Primitives

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..))
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

instance Gadget (CGadget SHA384) where
  type PrimitiveOf (CGadget SHA384) = SHA384
  type MemoryOf (CGadget SHA384) = CryptoCell SHA512
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA384Cxt sha) = cellStore cc sha
  finalize (CGadget cc) = SHA384Cxt <$> cellLoad cc
  apply (CGadget cc) n cptr = sha512Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)

instance PaddableGadget (CGadget SHA384)
