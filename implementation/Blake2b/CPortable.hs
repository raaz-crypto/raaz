{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- | The portable C-implementation of Blake2b.
module Blake2b.CPortable where

import Foreign.Ptr                ( Ptr, castPtr )
import Control.Monad.IO.Class     ( liftIO       )
import Data.Word
import Data.Proxy
import Data.Bits                  ( complement   )

import Raaz.Core
import Raaz.Core.Transfer         ( transferSize, unsafeTransfer )
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal
import Raaz.Verse.Blake2b.C.Portable

name :: String
name = "blake2b-libverse-c"

description :: String
description = "BLAKE2b Implementation in C exposed by libverse"

type Prim                    = BLAKE2b
type Internals               = Blake2bMem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS BLAKE2b
additionalBlocks = blocksOf 1 Proxy


------------------------ The foreign function calls  ---------------------

foreign import ccall unsafe
  "raaz/hash/blake2/common.h raazHashBlake2bPortableBlockCompress"
  c_blake2b_compress  :: AlignedPointer BufferAlignment
                      -> BLOCKS Prim
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

processBlocks buf blks =
  do uPtr   <- castPtr <$> uLengthCellPointer
     lPtr   <- castPtr <$>lLengthCellPointer
     hshPtr <- castPtr <$> hashCell128Pointer
     let wblks  = toEnum  $ fromEnum blks
         blkPtr = castPtr $ forgetAlignment buf
       in liftIO $ verse_blake2b_c_portable_iter
          blkPtr wblks uPtr lPtr hshPtr


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
  BYTES u  <- getULength
  BYTES l  <- getLLength
  hshPtr <- castPtr <$> hashCell128Pointer
  liftIO $ verse_blake2b_c_portable_last lastBlockPtr remBytes u l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy BLAKE2b) nbytes
        nBlocks      = atMost (transferSize padding) `mappend` toEnum (-1)
                                           -- all but the last block
        remBytes     = toEnum $ fromEnum $ nbytes - inBytes nBlocks
                                           -- Actual bytes in the last block.
        lastBlockPtr = castPtr (forgetAlignment buf `movePtr` nBlocks)
        --
        -- Finalisation FLAGS
        --
        f0 = complement 0
        f1 = 0
