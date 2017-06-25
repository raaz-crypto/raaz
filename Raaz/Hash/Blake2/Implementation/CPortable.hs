{-# LANGUAGE ForeignFunctionInterface   #-}
-- | The portable C-implementation of SHA1
module Raaz.Hash.Blake2.Implementation.CPortable
       ( implementation2b
       ) where

import Foreign.Ptr              ( Ptr )
import Data.Word
import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Blake2.Internal

-- | The portable C implementation of SHA1.
implementation2b :: Implementation BLAKE2b
implementation2b =  SomeHashI cPortable2b

cPortable2b :: HashI BLAKE2b Blake2bMem
cPortable2b = blake2bImplementation
              "blake2b-cportable"
              "BLAKE2b Implementation using portable C and Haskell FFI"
              compressIt
              c_blake2b_last
  where compressIt ptr = c_blake2b_compress ptr . fromEnum


foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: Pointer
                      -> Int
                      -> Ptr (BYTES Word64)
                      -> Ptr (BYTES Word64)
                      -> Ptr BLAKE2b
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableLastBlock"
  c_blake2b_last   :: Pointer
                   -> BYTES Int
                   -> BYTES Word64
                   -> BYTES Word64
                   -> Word64
                   -> Word64
                   -> Ptr BLAKE2b
                   -> IO ()




{-

void raazHashBlake2bPortableBlockCompress( Block2b *mesg, int nblocks,
					   Word2b *Upper, Word2b *Lower,
					   Blake2b h)

void raazHashBlake2bPortableLastBlock( Block2b mesg, int nbytes,
				       Word2b upper, Word2b lower,
				       Word2b f0 , Word2b f1,
				       Blake2b h)
-}
