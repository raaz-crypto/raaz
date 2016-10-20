{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
module Raaz.Hash.Sha.Util
       ( shaImplementation, portableC
       , length64Write
       , length128Write
       , Compressor
       ) where

import Control.Monad.IO.Class
import Data.Monoid                  ( (<>)      )
import Data.Word
import Foreign.Storable

import Raaz.Core
import Raaz.Core.Transfer
import Raaz.Hash.Internal


-- | The type alias for the raw compressor function.
type Compressor = Pointer  -- ^ The buffer to compress
                -> Int     -- ^ The number of blocks to compress
                -> Pointer -- ^ The cell memory containing the hash
                -> IO ()

-- | Creates an implementation for a sha hash given the compressor and
-- the length writer.
shaImplementation :: ( Primitive h
                     , Storable h
                     , Initialisable (HashMemory h) ()
                     )
                  => String                   -- ^ Name
                  -> String                   -- ^ Description
                  -> Compressor
                  -> (BITS Word64 -> WriteIO)
                  -> HashI h (HashMemory h)
shaImplementation nam des comp lenW
  = HashI { hashIName        = nam
          , hashIDescription = des
          , compress         = shaCompress comp
          , compressFinal    = shaCompressFinal undefined lenW comp
          }

{-# INLINE shaImplementation #-}
{-# INLINE portableC         #-}
portableC :: ( Primitive h
             , Storable h
             , Initialisable (HashMemory h) ()
             )
          => Compressor
          -> (BITS Word64 -> WriteIO)
          -> HashI h (HashMemory h)
portableC = shaImplementation "portable-c-ffi"
            "Implementation using portable C and Haskell FFI"



-- | The generic compress function for the sha family of hashes.
shaCompress :: (Primitive h, Storable h)
            => Compressor -- ^ raw compress function.
            -> Pointer    -- ^ buffer pointer
            -> BLOCKS h   -- ^ number of blocks
            -> MT (HashMemory h) ()
shaCompress comp ptr nblocks = do
  onSubMemory  hashCell $ withPointer $ comp ptr $ fromEnum nblocks
  updateLength nblocks

-- | The compressor for the last function.
shaCompressFinal :: (Primitive h, Storable h)
                  => h
                  -> (BITS Word64 -> WriteIO) -- ^ the length writer
                  -> Compressor             -- ^ the raw compressor
                  -> Pointer                -- ^ the buffer
                  -> BYTES Int              -- ^ the message length
                  -> MT (HashMemory h) ()
shaCompressFinal h lenW comp ptr msgLen = do
  updateLength msgLen
  totalBits <- extractLength
  let boundary = blocksOf 1 h
      pad    = shaPad msgLen boundary $ lenW totalBits
      blocks = atMost (bytesToWrite pad) `asTypeOf` boundary
      in do liftIO $ unsafeWrite pad ptr
            onSubMemory hashCell $ withPointer $ comp ptr $ fromEnum blocks

-- | Padding is message followed by a single bit 1 and a glue of zeros
-- followed by the length so that the message is aligned to the block boundary.
shaPad :: LengthUnit boundary
       => BYTES Int -- Message length
       -> boundary
       -> WriteIO   -- length write
       -> WriteIO
shaPad msgLen boundary lenW = glueWrites 0 boundary hdr lenW
  where skipMessage = skipWrite msgLen
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage <> oneBit


-- | The length encoding that uses 64-bits.
length64Write :: BITS Word64 ->  WriteIO
length64Write (BITS w) = write $ bigEndian w

-- | The length encoding that uses 128-bits.
length128Write :: BITS Word64 -> WriteIO
length128Write w = writeStorable (0 :: Word64) <> length64Write w
