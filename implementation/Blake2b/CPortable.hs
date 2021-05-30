{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Blake2b.
module Blake2b.CPortable where


import Foreign.Ptr                ( castPtr      )

import Raaz.Core
import Raaz.Core.Transfer.Unsafe
import Raaz.Core.Types.Internal
import Raaz.Primitive.HashMemory
import Raaz.Primitive.Blake2.Internal
import Raaz.Verse.Blake2b.C.Portable

name :: String
name = "libverse-c"

primName :: String
primName = "blake2b"

description :: String
description = "Blake2b Implementation in C exposed by libverse"

type Prim                    = Blake2b
type Internals               = Blake2bMem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Blake2b
additionalBlocks = blocksOf 1 Proxy


processBlocks :: BufferPtr
              -> BlockCount Blake2b
              -> Blake2bMem
              -> IO ()

processBlocks buf blks b2bmem =
  let uPtr   = castPtr $ uLengthCellPointer b2bmem
      lPtr   = castPtr $ lLengthCellPointer b2bmem
      hshPtr = castPtr $ hashCell128Pointer b2bmem
      --
      -- Type coersions to the appropriate type.
      --
      wblks  = toEnum  $ fromEnum blks
      blkPtr = castPtr $ forgetAlignment buf
  in verse_blake2b_c_portable_iter blkPtr wblks uPtr lPtr hshPtr


-- | Process the last bytes. The last block of the message (whether it
-- is padded or not) should necessarily be processed by the
-- processLast function as one needs to set the finalisation flag for
-- it.
--
-- Let us consider two cases.
--
-- 1. The message is empty. In which case the padding is 1-block
--    size. This needs to be processed as the last block
--
-- 2. If the message is non-empty then the padded message is the least
--    multiple @n@ of block size that is greater than or equal to the
--    input and hence is at least 1 block in size. Therefore, we
--    should be compressing a total @n-1@ blocks using the block
--    compression function at the last block using the finalisation
--    flags.
--
processLast :: BufferPtr
            -> BYTES Int
            -> Blake2bMem
            -> IO ()
processLast buf nbytes b2bmem = do
  unsafeTransfer padding $ forgetAlignment buf  -- pad the message
  processBlocks buf nBlocks b2bmem              -- process all but the last block
  --
  -- Handle the last block
  --
  BYTES u  <- getULength b2bmem
  BYTES l  <- getLLength b2bmem
  let hshPtr = castPtr $ hashCell128Pointer b2bmem
    in verse_blake2b_c_portable_last lastBlockPtr remBytes u l f0 f1 hshPtr

  where padding      = blake2Pad (Proxy :: Proxy Blake2b) nbytes
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
