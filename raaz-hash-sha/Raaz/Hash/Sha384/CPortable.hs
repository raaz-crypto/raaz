{-|

Portable C implementation of SHA384 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha384.CPortable
       ( CPortable
       ) where


import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha384.Type      ( SHA384(..) )
import Raaz.Hash.Sha512.Type      ( SHA512(..) )
import Raaz.Hash.Sha512.CPortable ( sha512Compress )

-- | Portable C implementation
data CPortable

instance Implementation CPortable where
  type PrimitiveOf CPortable = SHA384
  newtype Cxt CPortable = SHA384Cxt SHA512
  process (SHA384Cxt sha512) nblocks buf = fmap SHA384Cxt $ sha512Compress sha512 n buf
      where n = fromEnum nblocks

instance HashImplementation CPortable where
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
