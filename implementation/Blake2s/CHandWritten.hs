{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}


-- | The portable C-implementation of Blake2s.
module Blake2s.CHandWritten where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )

import Raaz.Core
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal


name :: String
name = "blake2s-c-handwritten"

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
              -> MT Internals ()

processBlocks buf blks =
  do l      <- getLength
     hashCellPointer >>= liftIO . c_blake2s_compress buf blks l
     updateLength blks

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> MT Internals ()
processLast buf nbytes  = do
  unsafeTransfer padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks                  -- process all but the last block
  --
  -- Handle the last block
  --
  l      <- getLength
  hshPtr <- hashCellPointer
  liftIO $ c_blake2s_last lastBlockPtr remBytes l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy Prim) nbytes
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
