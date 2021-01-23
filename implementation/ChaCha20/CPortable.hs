{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Blake2b.
module ChaCha20.CPortable where

import           Foreign.Ptr                ( castPtr )
import qualified Data.Vector.Unboxed as V

import           Raaz.Core
import           Raaz.Core.Types.Internal
import           Raaz.Primitive.ChaCha20.Internal
import           Raaz.Verse.ChaCha20.C.Portable

name :: String
name = "chacha20-libverse-c"

description :: String
description = "ChaCha20 Implementation in C exposed by libverse"

type Prim                    = ChaCha20
type Internals               = ChaCha20Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount ChaCha20
additionalBlocks = blocksOf 1 Proxy

processBlocks :: BufferPtr
              -> BlockCount Prim
              -> Internals
              -> IO ()

processBlocks = runBlockProcess verse_chacha20_c_portable


-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast buf = processBlocks buf . atLeast


-- | The xchacha20Setup  does the following to the internal state
--
-- 1. Replaces the key stored in the keyCell using the hchacah20 hashing function
--
-- 2. Initialises the ivcell with the last two words in the xiv value.
--
-- As a result the internal state is ready to start encrypting using
-- the xchacha20 variant.
--
xchacha20Setup :: Nounce XChaCha20 -> Internals -> IO ()
xchacha20Setup (XNounce tup) mem = do
  verse_hchacha20_c_portable keyPtr h0 h1 h2 h3
  -- In the above step, the key gets replaced by the subkey obtained
  -- from the hchacha20 hash. We also set the ivcell appropriately
  initialise iv $ ivCell mem
  where keyPtr = castPtr $ keyCellPtr mem
        [LE h0,LE h1,LE h2, LE h3, h4, h5] = V.toList $ unsafeToVector tup
        iv  = Nounce $ unsafeFromList [0, h4, h5] :: Nounce ChaCha20


-- | Copy the key from the memory cell chacha20Mem.
copyKey :: Dest ChaCha20Mem -> Src (MemoryCell (Key ChaCha20)) -> IO ()
copyKey = copyCell . fmap keyCell

-------------- Helper function for running an iterator -----------
runBlockProcess :: ( Ptr buf ->
                     Word64  ->
                     Ptr a   ->
                     Ptr b   ->
                     Ptr c   ->
                     IO ()
                   )
                -> BufferPtr
                -> BlockCount Prim
                -> Internals
                -> IO ()
runBlockProcess func buf blks mem =
  let keyPtr     = castPtr $ keyCellPtr mem
      ivPtr      = castPtr $ ivCellPtr mem
      counterPtr = castPtr $ counterCellPtr mem
      blkPtr     = castPtr $ forgetAlignment buf
      wBlks      = toEnum  $ fromEnum blks
  in func blkPtr wBlks keyPtr ivPtr counterPtr
