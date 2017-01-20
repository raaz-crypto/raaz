{-# LANGUAGE ForeignFunctionInterface   #-}
-- | The portable C-implementation of SHA1
module Raaz.Hash.Sha1.Implementation.CPortable
       ( implementation
       ) where

import Foreign.Ptr              ( Ptr )
import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha1.Internal

-- | The portable C implementation of SHA1.
implementation :: Implementation SHA1
implementation =  SomeHashI cPortable

cPortable :: HashI SHA1 (HashMemory SHA1)
cPortable = shaImplementation
            "sha1-cportable"
            "Sha1 Implementation using portable C and Haskell FFI"
            c_sha1_compress length64Write

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: Pointer -> Int -> Ptr SHA1 -> IO ()
