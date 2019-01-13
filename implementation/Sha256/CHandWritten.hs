{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of SHA256.
module Sha256.CHandWritten
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Proxy

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha2.Internal (SHA256, Sha256Mem, process256Last)

name :: String
name = "sha256-c-handwritten"

description :: String
description = "Hand written SHA256 Implementation using portable C and Haskell FFI"

type Prim                    = SHA256
type Internals               = Sha256Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS SHA256
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
   c_sha256_compress  :: AlignedPointer BufferAlignment
                      -> BLOCKS SHA256
                      -> Ptr SHA256
                      -> IO ()


compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS SHA256
               -> MT Internals ()
compressBlocks buf blks =  hashCellPointer >>= liftIO . c_sha256_compress buf blks


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS SHA256
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength blks

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast = process256Last processBlocks
