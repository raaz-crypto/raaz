{-# LANGUAGE ForeignFunctionInterface   #-}
-- | The portable C-implementation of SHA1
module Raaz.Hash.Blake2.Implementation.CPortable
       ( implementation2b
       , implementation2s
       ) where

import Foreign.Ptr              ( Ptr )
import Data.Word
import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Blake2.Internal

-- | The portable C implementation of BLAKE2b.
implementation2b :: Implementation BLAKE2b
implementation2b =  SomeHashI cPortable2b

-- | The portable C implementation of BLAKE2s.
implementation2s :: Implementation BLAKE2s
implementation2s =  SomeHashI cPortable2s


cPortable2b :: HashI BLAKE2b Blake2bMem
cPortable2b = blake2bImplementation
              "blake2b-cportable"
              "BLAKE2b Implementation using portable C and Haskell FFI"
              compressIt
              c_blake2b_last
  where compressIt ptr = c_blake2b_compress ptr . fromEnum


cPortable2s :: HashI BLAKE2s Blake2sMem
cPortable2s = blake2sImplementation
              "blake2s-cportable"
              "BLAKE2s Implementation using portable C and Haskell FFI"
              compressIt
              c_blake2s_last
  where compressIt ptr = c_blake2s_compress ptr . fromEnum





------------------------- FFI For Blake2b -------------------------------------

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


------------------------- FFI For Blake2s -------------------------------------


foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableBlockCompress"
  c_blake2s_compress  :: Pointer
                      -> Int
                      -> BYTES Word64
                      -> Ptr BLAKE2s
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableLastBlock"
  c_blake2s_last   :: Pointer
                   -> BYTES Int
                   -> BYTES Word64
                   -> Word32
                   -> Word32
                   -> Ptr BLAKE2s
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
