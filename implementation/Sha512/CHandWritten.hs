{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Sha512.
module Sha512.CHandWritten
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (Sha512, Sha512Mem, process512Last)

name :: String
name = "sha512-c-handwritten"

description :: String
description = "Hand written Sha512 Implementation using portable C and Haskell FFI"

type Prim                    = Sha512
type Internals               = Sha512Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS Sha512
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: AlignedPointer BufferAlignment
                     -> BLOCKS Sha512
                     -> Ptr Sha512
                     -> IO ()


compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS Sha512
               -> MT Internals ()
compressBlocks buf blks =  hashCell128Pointer
                           >>= liftIO . c_sha512_compress buf blks


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Sha512
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength128 blks

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast = process512Last processBlocks
