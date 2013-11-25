{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha384.CPortable
       ( CPortable
       ) where


import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha384.Type
import Raaz.Hash.Sha512.Type      ( SHA512(..) )
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

-- | Portable C implementation
data CPortable = CPortable (CryptoCell SHA512)

instance Gadget CPortable where
  type PrimitiveOf CPortable = SHA384
  type MemoryOf CPortable = CryptoCell SHA512
  newGadget cc = return $ CPortable cc
  initialize (CPortable cc) (SHA384IV sha) = cellStore cc sha
  finalize (CPortable cc) = sha512Tosha384 `fmap` cellLoad cc
    where sha512Tosha384 (SHA512 h0 h1 h2 h3 h4 h5 _ _)
            = (SHA384 h0 h1 h2 h3 h4 h5)
  apply (CPortable cc) n cptr = sha512Compress cc n' cptr
    where n' = blocksOf (fromIntegral n) (undefined :: SHA512)

instance SafeGadget CPortable
instance HashGadget CPortable
