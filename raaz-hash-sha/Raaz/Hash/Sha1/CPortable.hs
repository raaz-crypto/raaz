{-|

Portable C implementation of SHA1 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha1/portable.c  #-}

module Raaz.Hash.Sha1.CPortable
       ( CPortable
       ) where

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

import Raaz.Hash.Sha1.Type

-- | Portable C implementation
data CPortable = CPortable (CryptoCell SHA1)

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: CryptoPtr -> Int -> CryptoPtr -> IO ()

sha1Compress :: CryptoCell SHA1 -> BLOCKS SHA1 -> CryptoPtr -> IO ()
{-# INLINE sha1Compress #-}
sha1Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha1_compress ptr n buffer
        n = fromEnum nblocks

instance Gadget CPortable where
  type PrimitiveOf CPortable = SHA1
  type MemoryOf CPortable = CryptoCell SHA1
  newGadget cc = return $ CPortable cc
  initialize (CPortable cc) (SHA1IV sha1) = cellStore cc sha1
  finalize (CPortable cc) = cellLoad cc

instance SafeGadget CPortable where
  applySafe (CPortable cc) n cptr = sha1Compress cc n cptr

instance HashGadget CPortable where
