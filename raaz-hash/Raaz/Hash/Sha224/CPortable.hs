{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable
       ( CPortable
       ) where

import Raaz.Memory
import Raaz.Primitives

import Raaz.Hash.Sha224.Type
import Raaz.Hash.Sha256.Type      ( SHA256(..) )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

-- | Portable C implementation
data CPortable = CPortable (CryptoCell SHA256)

instance Gadget CPortable where
  type PrimitiveOf CPortable = SHA224
  type MemoryOf CPortable = CryptoCell SHA256
  newGadgetWithMemory cc = return $ CPortable cc
  initialize (CPortable cc) (SHA224IV sha) = cellStore cc sha
  finalize (CPortable cc) = sha256Tosha224 `fmap` cellLoad cc
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
  apply (CPortable cc) n cptr = sha256Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA256)
