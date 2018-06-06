{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of SHA256.
module Raaz.Primitive.Sha256.Implementation.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Monoid
import Data.Bits
import Data.Word
import Data.Proxy

import Raaz.Core
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha256.Internal


name :: String
name = "sha256-cportable"

description :: String
description = "SHA256 Implementation using portable C and Haskell FFI"

type Prim                    = SHA256
type Internals               = Sha256Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS SHA256
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Pointer -> Int -> Ptr SHA256 -> IO ()


compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS SHA256
               -> MT Internals ()
compressBlocks buf blks =  hashCellPointer >>= liftIO . c_sha256_compress (forgetAlignment buf) (fromEnum blks)


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS SHA256
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength blks



-- | Padding is message followed by a single bit 1 and a glue of zeros
-- followed by the length so that the message is aligned to the block boundary.
padding :: BYTES Int    -- Data in buffer.
        -> BYTES Word64 -- Message length
        -> WriteM (MT Internals)
padding bufSize msgLen  = glueWrites 0 boundary hdr lengthWrite
  where skipMessage = skipWrite bufSize
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage <> oneBit
        boundary    = blocksOf 1 (Proxy :: Proxy SHA256)
        lengthWrite = write $ bigEndian (shiftL w 3)
        BYTES w     = msgLen

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf nbytes  = do
  updateLength nbytes
  totalBytes  <- getLength
  let pad      = padding nbytes totalBytes
      blocks   = atMost $ bytesToWrite pad
      in unsafeWrite pad (forgetAlignment buf) >> compressBlocks buf blocks
