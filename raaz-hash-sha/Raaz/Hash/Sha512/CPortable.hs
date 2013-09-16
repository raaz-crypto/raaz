{-|

Portable C implementation of SHA512 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha512/portable.c  #-}

module Raaz.Hash.Sha512.CPortable
       ( CPortable
       , sha512Compress
       ) where

import Foreign.Ptr

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types

import Raaz.Hash.Sha512.Type

-- | Portable C implementation
data CPortable = CPortable (CryptoCell SHA512)

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: Ptr SHA512 -> Int -> CryptoPtr -> IO ()

sha512Compress :: CryptoCell SHA512 -> BLOCKS SHA512 -> CryptoPtr -> IO ()
sha512Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha512_compress (castPtr ptr) n buffer
        n = fromEnum nblocks
{-# INLINE sha512Compress #-}

instance Gadget CPortable where
  type PrimitiveOf CPortable = SHA512
  type MemoryOf CPortable = CryptoCell SHA512
  newGadget cc = return $ CPortable cc
  initialize (CPortable cc) (SHA512IV sha1) = cellStore cc sha1
  finalize (CPortable cc) = cellLoad cc
  apply (CPortable cc) n cptr = sha512Compress cc n cptr

instance SafeGadget CPortable
instance HashGadget CPortable
