{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2s.
module Blake2s.CHandWritten where

import Raaz.Core
import Raaz.Core.Transfer.Unsafe
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal


name :: String
name = "handwritten-c"

primName :: String
primName = "blake2s"

description :: String
description = "Hand written Blake2s Implementation using portable C and Haskell FFI"

type Prim                    = Blake2s
type Internals               = Blake2sMem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Prim
additionalBlocks = blocksOf 1 Proxy

------------------------- FFI For Blake2s -------------------------------------


foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableBlockCompress"
  c_blake2s_compress  :: BufferPtr
                      -> BlockCount Blake2s
                      -> BYTES Word64
                      -> Ptr Prim
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableLastBlock"
  c_blake2s_last   :: BlockPtr Prim
                   -> BYTES Int
                   -> BYTES Word64
                   -> Word32
                   -> Word32
                   -> Ptr Prim
                   -> IO ()
--
processBlocks :: BufferPtr
              -> BlockCount Prim
              -> Internals
              -> IO ()

processBlocks buf blks b2smem =
  let hshPtr = hashCellPointer b2smem
  in do l      <- getLength b2smem
        c_blake2s_compress buf blks l hshPtr
        updateLength blks b2smem

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast buf nbytes  b2smem = do
  unsafeTransfer padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks b2smem              -- process all but the last block
  --
  -- Handle the last block
  --
  l      <- getLength b2smem
  c_blake2s_last lastBlockPtr remBytes l f0 f1 hshPtr
  where hshPtr = hashCellPointer b2smem
        padding      = blake2Pad (Proxy :: Proxy Prim) nbytes
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
