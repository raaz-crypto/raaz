{-|

Portable C implementation of SHA256 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE TypeFamilies             #-}
{-# CFILES raaz/hash/sha256/portable.c  #-}

module Raaz.Hash.Sha256.CPortable
       ( CPortable
       , sha256Compress
       ) where


import Foreign.Ptr

import Raaz.Memory
import Raaz.Primitives
import Raaz.Types

import Raaz.Hash.Sha256.Type

-- | Portable C implementation
data CPortable = CPortable (CryptoCell SHA256)

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Ptr SHA256 -> Int -> CryptoPtr -> IO ()

sha256Compress :: CryptoCell SHA256 -> BLOCKS SHA256 -> CryptoPtr -> IO ()
sha256Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha256_compress (castPtr ptr) n buffer
        n = fromEnum nblocks
{-# INLINE sha256Compress #-}

instance Gadget CPortable where
  type PrimitiveOf CPortable = SHA256
  type MemoryOf CPortable = CryptoCell SHA256
  newGadgetWithMemory cc = return $ CPortable cc
  initialize (CPortable cc) (SHA256IV sha1) = cellStore cc sha1
  finalize (CPortable cc) = cellLoad cc
  apply (CPortable cc) n cptr = sha256Compress cc n cptr
