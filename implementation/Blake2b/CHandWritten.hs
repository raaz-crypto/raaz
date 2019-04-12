{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2b.
module Blake2b.CHandWritten where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )

import Raaz.Core
import Raaz.Core.Transfer         ( transferSize, unsafeTransfer )
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal


name :: String
name = "blake2b-c-handwritten"

description :: String
description = "Hand written Blake2b Implementation in portable C and Haskell FFI"

type Prim                    = Blake2b
type Internals               = Blake2bMem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS Blake2b
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: AlignedPointer BufferAlignment
                      -> BLOCKS Prim
                      -> Ptr (BYTES Word64)
                      -> Ptr (BYTES Word64)
                      -> Ptr Blake2b
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableLastBlock"
  c_blake2b_last   :: Pointer
                   -> BYTES Int
                   -> BYTES Word64
                   -> BYTES Word64
                   -> Word64
                   -> Word64
                   -> Ptr Blake2b
                   -> IO ()

--
processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Blake2b
              -> MT Blake2bMem ()

processBlocks buf blks = do uPtr   <- uLengthCellPointer
                            lPtr   <- lLengthCellPointer
                            hshPtr <- hashCell128Pointer
                            liftIO $ c_blake2b_compress buf blks uPtr lPtr hshPtr

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Blake2bMem ()
processLast buf nbytes  = do
  unsafeTransfer padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks                     -- process all but the last block
  --
  -- Handle the last block
  --
  u      <- getULength
  l      <- getLLength
  hshPtr <- hashCell128Pointer
  liftIO $ c_blake2b_last lastBlockPtr remBytes u l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy Blake2b) nbytes
        nBlocks      = atMost (transferSize padding) `mappend` toEnum (-1)
                                           -- all but the last block
        remBytes     = nbytes - inBytes nBlocks
                                           -- Actual bytes in the last block.
        lastBlockPtr = forgetAlignment buf `movePtr` nBlocks
        --
        -- Finalisation FLAGS
        --
        f0 = complement 0
        f1 = 0
