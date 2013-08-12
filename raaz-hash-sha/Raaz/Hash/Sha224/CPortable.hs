{-|

Portable C implementation of SHA224 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}

module Raaz.Hash.Sha224.CPortable
       ( CPortable
       ) where


import Raaz.Primitives
import Raaz.Primitives.Hash

import Raaz.Hash.Sha224.Type      ( SHA224(..) )
import Raaz.Hash.Sha256.Type      ( SHA256(..) )
import Raaz.Hash.Sha256.CPortable ( sha256Compress )

-- | Portable C implementation
data CPortable

instance Implementation CPortable where
  type PrimitiveOf CPortable = SHA224
  newtype Cxt CPortable = SHA224Cxt SHA256
  process (SHA224Cxt sha224) nblocks buf = fmap SHA224Cxt $ sha256Compress sha224 n buf
      where n = fromEnum nblocks

instance HashImplementation CPortable where
  startHashCxt = SHA224Cxt $ SHA256 0xc1059ed8
                                    0x367cd507
                                    0x3070dd17
                                    0xf70e5939
                                    0xffc00b31
                                    0x68581511
                                    0x64f98fa7
                                    0xbefa4fa4

  finaliseHash (SHA224Cxt h) = sha256Tosha224 h
    where sha256Tosha224 (SHA256 h0 h1 h2 h3 h4 h5 h6 _)
            = SHA224 h0 h1 h2 h3 h4 h5 h6
