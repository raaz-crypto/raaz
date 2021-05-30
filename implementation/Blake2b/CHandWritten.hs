{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2b.
module Blake2b.CHandWritten where

import Raaz.Core
import Raaz.Core.Transfer.Unsafe
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal


name :: String
name = "handwritten-c"

primName :: String
primName = "blake2b"

description :: String
description = "Hand written Blake2b Implementation in portable C"

type Prim                    = Blake2b
type Internals               = Blake2bMem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Blake2b
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: BufferPtr
                      -> BlockCount Prim
                      -> Ptr (BYTES Word64)
                      -> Ptr (BYTES Word64)
                      -> Ptr Blake2b
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableLastBlock"
  c_blake2b_last   :: BlockPtr Prim
                   -> BYTES Int
                   -> BYTES Word64
                   -> BYTES Word64
                   -> Word64
                   -> Word64
                   -> Ptr Blake2b
                   -> IO ()

--
processBlocks :: BufferPtr
              -> BlockCount Blake2b
              -> Blake2bMem
              -> IO ()

processBlocks buf blks b2bmem =
  let uPtr = uLengthCellPointer b2bmem
      lPtr = lLengthCellPointer b2bmem
      hshPtr = hashCell128Pointer b2bmem
  in c_blake2b_compress buf blks uPtr lPtr hshPtr

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Blake2bMem
            -> IO ()
processLast buf nbytes b2bmem  = do
  unsafeTransfer padding buf         -- pad the message
  processBlocks buf nBlocks b2bmem   -- process all but the last block
  --
  -- Handle the last block
  --
  let
      hshPtr = hashCell128Pointer b2bmem
    in  do u <- getULength b2bmem
           l <- getLLength b2bmem
           c_blake2b_last lastBlockPtr remBytes u l f0 f1 hshPtr

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
