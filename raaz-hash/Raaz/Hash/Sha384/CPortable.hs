{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}

module Raaz.Hash.Sha384.CPortable () where


import Raaz.Memory
import Raaz.Primitives

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..) )
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

instance Gadget (CGadget SHA384) where
  type PrimitiveOf (CGadget SHA384) = SHA384
  type MemoryOf (CGadget SHA384) = CryptoCell SHA512
  newGadgetWithMemory = return . CGadget
  initialize (CGadget cc) (SHA384IV sha) = cellStore cc sha
  finalize (CGadget cc) = sha512Tosha384 `fmap` cellLoad cc
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = (SHA384 h0 h1 h2 h3 h4 h5)
  apply (CGadget cc) n cptr = sha512Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)
