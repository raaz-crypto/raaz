{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2b.
module Raaz.Hash.Blake2b.CPortable where

import Foreign.Ptr                ( Ptr          )
import Control.Monad.IO.Class     ( liftIO       )
import Control.Monad.Trans.Reader ( withReaderT  )
import GHC.TypeLits
import Data.Word
import Data.Proxy
import Data.Bits                  ( complement   )

import Raaz.Core
import Raaz.Core.Transfer         ( bytesToWrite, unsafeWrite )
import Raaz.Hash.Blake2.Internal

name :: String
name = "blake2b-cportable"

description :: String
description = "BLAKE2b Implementation using portable C and Haskell FFI"

type Prim                    = BLAKE2b
type Internals               = Blake2bMem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS BLAKE2b
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: AlignedPointer BufferAlignment
                      -> Int
                      -> Ptr (BYTES Word64)
                      -> Ptr (BYTES Word64)
                      -> Ptr BLAKE2b
                      -> IO ()

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableLastBlock"
  c_blake2b_last   :: Pointer
                   -> BYTES Int
                   -> BYTES Word64
                   -> BYTES Word64
                   -> Word64
                   -> Word64
                   -> Ptr BLAKE2b
                   -> IO ()

--
processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS BLAKE2b
              -> MT Blake2bMem ()

processBlocks buf blks = do uPtr   <- withReaderT uLengthCell getCellPointer
                            lPtr   <- withReaderT lLengthCell getCellPointer
                            hshPtr <- withReaderT blake2bCell getCellPointer
                            liftIO $ c_blake2b_compress buf (fromEnum blks) uPtr lPtr hshPtr

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Blake2bMem ()
processLast buf nbytes  = do
  unsafeWrite padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks                  -- process all but the last block
  --
  -- Handle the last block
  --
  u      <- withReaderT uLengthCell extract
  l      <- withReaderT lLengthCell extract
  hshPtr <- withReaderT blake2bCell getCellPointer
  liftIO $ c_blake2b_last lastBlockPtr remBytes u l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy BLAKE2b) nbytes
        nBlocks      = atMost (bytesToWrite padding) <> toEnum (-1) -- all but the last block
        remBytes     = nbytes - inBytes nBlocks                     -- Actual bytes in the last block.
        lastBlockPtr = forgetAlignment buf `movePtr` nBlocks
        --
        -- Finalisation FLAGS
        --
        f0 = complement 0
        f1 = 0
