{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGAUGE DataKinds                  #-}
-- | The portable C-implementation of Blake2b.
module Raaz.Hash.Blake2b.Implementation.CPortable
       (
       ) where

import Foreign.Ptr              ( Ptr )
import Data.Word
import Data.Proxy
import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Blake2.Internal

name :: String
name = "blake2b-cportable"

description :: String
description = "BLAKE2b Implementation using portable C and Haskell FFI"

type Prim            = Blake2b
type Internals       = Blake2bMem
type BufferAlignment = 32


additionalBlocks :: BLOCKS Blake2bMem
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: Pointer
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

processBlocks buf blks = do uPtr   <- onSubMemory uLengthCell getCellPointer
                            lPtr   <- onSubMemory lLengthCell getCellPointer
                            hshPtr <- onSubMemory blake2bCell getCellPointer
                            liftIO $ c_blake2b_compress buf blks uPtr lPtr hshPtr

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Blake2bMem ()
processLast buf nbytes  = do
  unsafeWrite padding buf   -- pad the message
  processBlocks buf nBlocks -- process all but the last block
  --
  -- Handle the last block
  --
  u      <- onSubMemory uLengthCell extract
  l      <- onSubMemory lLengthCell extract
  hshPtr <- onSubMemory blake2bCell getCellPointer
  liftIO $ c_blake2b_last remBytes u l f0 f1 hshPtr

  where padding  = blake2Pad (Proxy :: Proxy Blake2b) nbytes
        nBlocks  = atMost (bytesToWrite padding) <> toEnum (-1) -- all but the last block
        remBytes = nbytes - inBytes nBlocks -- Actual bytes in the last block.
        f0 = complement 0
        f1 = 0
