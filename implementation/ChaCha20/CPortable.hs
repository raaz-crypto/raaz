{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Blake2b.
module ChaCha20.CPortable where

import           Control.Monad.Reader       ( withReaderT  )
import           Foreign.Ptr                ( castPtr, Ptr )
import           Control.Monad.IO.Class     ( liftIO       )
import qualified Data.Vector.Unboxed as V

import           Raaz.Core
import           Raaz.Core.Types.Internal
import           Raaz.Primitive.ChaCha20.Internal
import           Raaz.Verse.Chacha20.C.Portable

name :: String
name = "chacha20-libverse-c"

description :: String
description = "ChaCha20 Implementation in C exposed by libverse"

type Prim                    = ChaCha20
type Internals               = ChaCha20Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS ChaCha20
additionalBlocks = blocksOf 1 Proxy

processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()

processBlocks = runBlockProcess verse_chacha20_c_portable


-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
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
xchacha20Setup :: Nounce XChaCha20 -> MT Internals ()
xchacha20Setup (XNounce tup) = do
  keyPtr <- castPtr <$> keyCellPtr
  liftIO $ verse_hchacha20_c_portable keyPtr h0 h1 h2 h3
  -- In the above step, the key gets replaced by the subkey obtained
  -- from the hchacha20 hash. We also set the ivcell appropriately
  withReaderT ivCell $ initialise iv
  where [LE h0,LE h1,LE h2, LE h3, h4, h5] = V.toList $ unsafeToVector tup
        iv  = Nounce $ unsafeFromList [0, h4, h5] :: Nounce ChaCha20


-- | Copy the key from the memory cell chacha20Mem.
copyKey :: Dest ChaCha20Mem -> Src (MemoryCell (Key ChaCha20)) -> IO ()
copyKey = copyMemory . fmap keyCell

-------------- Helper function for running an iterator -----------
runBlockProcess :: ( Ptr buf ->
                     Word64  ->
                     Ptr a   ->
                     Ptr b   ->
                     Ptr c   ->
                     IO ()
                   )
                -> AlignedPointer BufferAlignment
                -> BLOCKS Prim
                -> MT Internals ()
runBlockProcess func buf blks =
  do keyPtr     <- castPtr <$> keyCellPtr
     ivPtr      <- castPtr <$> ivCellPtr
     counterPtr <- castPtr <$> counterCellPtr
     let blkPtr = castPtr $ forgetAlignment buf
         wBlks  = toEnum  $ fromEnum blks
         in liftIO $ func blkPtr wBlks keyPtr ivPtr counterPtr
