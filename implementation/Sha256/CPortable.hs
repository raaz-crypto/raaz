{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of SHA256.
module Sha256.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( castPtr      )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Bits
import Data.Word
import Data.Proxy

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha256.Internal

import Raaz.Verse.Sha256.C.Portable

name :: String
name = "sha256-libverse-c"

description :: String
description = "SHA256 Implementation in C exposed by libverse"

type Prim                    = SHA256
type Internals               = Sha256Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS SHA256
additionalBlocks = blocksOf 1 Proxy

-- | The compression algorithm.
compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS SHA256
               -> MT Internals ()
compressBlocks buf blks = do hPtr <- castPtr <$> hashCellPointer
                             let blkPtr = castPtr $ forgetAlignment buf
                                 wBlks  = toEnum $ fromEnum blks
                               in liftIO $ verse_sha256_c_portable blkPtr wBlks hPtr


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
  where skipMessage = skip bufSize
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage `mappend` oneBit
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
      blocks   = atMost $ transferSize pad
      in unsafeTransfer pad (forgetAlignment buf) >> compressBlocks buf blocks
