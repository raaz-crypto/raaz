{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2s.
module Raaz.Primitive.Blake2s.CPortable where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Monoid
import Data.Word
import Data.Proxy
import Data.Bits                  ( complement   )

import Raaz.Core
import Raaz.Core.Transfer         ( bytesToWrite, unsafeWrite )
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal


name :: String
name = "blake2s-cportable"

description :: String
description = "BLAKE2s Implementation using portable C and Haskell FFI"

type Prim                    = BLAKE2s
type Internals               = Blake2sMem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS Prim
additionalBlocks = blocksOf 1 Proxy

------------------------- FFI For Blake2s -------------------------------------


foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableBlockCompress"
  c_blake2s_compress  :: Pointer
                      -> Int
                      -> BYTES Word64
                      -> Ptr Prim
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2sPortableLastBlock"
  c_blake2s_last   :: Pointer
                   -> BYTES Int
                   -> BYTES Word64
                   -> Word32
                   -> Word32
                   -> Ptr Prim
                   -> IO ()
--
processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()

processBlocks buf blks =
  do l      <- getLength
     hashCellPointer >>= liftIO . c_blake2s_compress (forgetAlignment buf) (fromEnum blks) l
     updateLength blks

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf nbytes  = do
  unsafeWrite padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks                  -- process all but the last block
  --
  -- Handle the last block
  --
  l      <- getLength
  hshPtr <- hashCellPointer
  liftIO $ c_blake2s_last lastBlockPtr remBytes l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy Prim) nbytes
        nBlocks      = atMost (bytesToWrite padding) <> toEnum (-1) -- all but the last block
        remBytes     = nbytes - inBytes nBlocks                     -- Actual bytes in the last block.
        lastBlockPtr = forgetAlignment buf `movePtr` nBlocks
        --
        -- Finalisation FLAGS
        --
        f0 = complement 0
        f1 = 0
