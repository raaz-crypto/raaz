{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of SHA512.
module Sha512.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Bits
import Data.Word
import Data.Proxy

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Sha512.Internal


name :: String
name = "sha512-cportable"

description :: String
description = "SHA512 Implementation using portable C and Haskell FFI"

type Prim                    = SHA512
type Internals               = Sha512Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS SHA512
additionalBlocks = blocksOf 1 Proxy

------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: AlignedPointer BufferAlignment
                     -> BLOCKS SHA512
                     -> Ptr SHA512
                     -> IO ()


compressBlocks :: AlignedPointer BufferAlignment
               -> BLOCKS SHA512
               -> MT Internals ()
compressBlocks buf blks =  hashCell128Pointer
                           >>= liftIO . c_sha512_compress buf blks


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS SHA512
              -> MT Internals ()
processBlocks buf blks = compressBlocks buf blks >> updateLength128 blks



-- | Padding is message followed by a single bit 1 and a glue of zeros
-- followed by the length so that the message is aligned to the block boundary.
padding :: BYTES Int    -- Data in buffer.
        -> BYTES Word64 -- Message length higher
        -> BYTES Word64 -- Message length lower
        -> WriteM (MT Internals)
padding bufSize uLen lLen  = glueWrites 0 boundary hdr lengthWrite
  where skipMessage = skip bufSize
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage `mappend` oneBit
        boundary    = blocksOf 1 (Proxy :: Proxy SHA512)
        lengthWrite = write (bigEndian up) `mappend` write (bigEndian lp)
        BYTES up    = shiftL uLen 3 .|. shiftR lLen 61
        BYTES lp    = shiftL lLen 3

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf nbytes  = do
  updateLength128 nbytes
  uLen  <- getULength
  lLen  <- getLLength
  let pad      = padding nbytes uLen lLen
      blocks   = atMost $ transferSize pad
      in unsafeTransfer pad (forgetAlignment buf) >> compressBlocks buf blocks
