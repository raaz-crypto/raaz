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
                  -> (BITS Word64 -> Write)
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
          -> (BITS Word64 -> Write)
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
  liftSubMT  hashCell $ withPointer $ comp ptr $ fromEnum nblocks
  updateLength nblocks

-- | The compressor for the last function.
shaCompressFinal :: (Primitive h, Storable h)
                  => h
                  -> (BITS Word64 -> Write) -- ^ the length writer
                  -> Compressor             -- ^ the raw compressor
                  -> Pointer                -- ^ the buffer
                  -> BYTES Int              -- ^ the message length
                  -> MT (HashMemory h) ()
shaCompressFinal h lenW comp ptr nbytes = do
  updateLength nbytes
  totalBits <- extractLength
  let pad       = paddedMesg (lenW totalBits) h nbytes
      blocks    = atMost (bytesToWrite pad) `asTypeOf` blocksOf 1 h
    in do liftIO $ unsafeWrite pad ptr
          liftSubMT hashCell $ withPointer $ comp ptr $ fromEnum blocks

-- | The length encoding that uses 64-bits.
length64Write :: BITS Word64 ->  Write
length64Write (BITS w) = write $ bigEndian w

-- | The length encoding that uses 128-bits.
length128Write :: BITS Word64 -> Write
length128Write w = writeStorable (0 :: Word64) <> length64Write w

-- | The padding to be used
paddedMesg :: Primitive h
           => Write        -- ^ The length encoding
           -> h            -- ^ The hash
           -> BYTES Int    -- ^ The message length
           -> Write
paddedMesg lenW h msgLen = start <> zeros <> lenW
   where start      = skipWrite msgLen <> writeStorable (0x80 :: Word8)
         zeros      = writeBytes    0    sz
         totalBytes = bytesToWrite start + bytesToWrite lenW
         sz         = inBytes (atLeast totalBytes `asTypeOf` blocksOf 1 h)
                    - totalBytes
