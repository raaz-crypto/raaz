{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE ConstraintKinds            #-}

module Raaz.Hash.Sha.Util
       ( shaImplementation, portableC
       -- ** Writing message lengths.
       -- $lengthwrites$
       , length64Write
       , length128Write
       , Compressor
       ) where

import Data.Monoid                  ( (<>)      )
import Data.Word
import Foreign.Storable

import Raaz.Core
import Raaz.Core.Transfer
import Raaz.Hash.Internal

-- | The utilities in this module can be used on primitives which
-- satisfies the following constraint.
type IsSha h    = (Primitive h, Storable h, Memory (HashMemory h))

-- | All actions here are in the following monad
type ShaMonad h = MT (HashMemory h)

-- | The Writes used in this module.
type ShaWrite h = WriteM (ShaMonad h)
--
-- The message in the sha1 family of hashes pads the message, the last
-- few bytes of which are used to store the message length. Hashes
-- like sha1, sha256 etc writes the message lengths in 64-bits while
-- sha512 uses lengths in 128 bits. The generic writes `length64Write`
-- and `length128Write` are write actions that support this.

-- | Type that captures length writes.
type LengthWrite h = BITS Word64 -> ShaWrite h

-- | The length encoding that uses 64-bits.
length64Write :: LengthWrite h
length64Write (BITS w) = write $ bigEndian w

-- | The length encoding that uses 128-bits.
length128Write :: LengthWrite h
length128Write w = writeStorable (0 :: Word64) <> length64Write w


-- | The type alias for the raw compressor function. The compressor function
-- does not need to know the length of the message so far and hence
-- this is not supposed to update lengths.
type Compressor = Pointer  -- ^ The buffer to compress
                -> Int     -- ^ The number of blocks to compress
                -> Pointer -- ^ The cell memory containing the hash
                -> IO ()

-- | Action on a Buffer
type ShaBufferAction bufSize h = Pointer       -- ^ The data buffer
                               -> bufSize      -- ^ Total data present
                               -> ShaMonad h ()

-- | Lifts the raw compressor to a buffer action. This function does not update
-- the lengths.
liftCompressor          :: IsSha h => Compressor -> ShaBufferAction (BLOCKS h) h
liftCompressor comp ptr = onSubMemory hashCell . withPointer . comp ptr . fromEnum


-- | The combinator `shaBlocks` on an input compressor @comp@ gives a buffer action
-- that process blocks of data.
shaBlocks :: Primitive h
          => ShaBufferAction (BLOCKS h) h -- ^ the compressor function
          -> ShaBufferAction (BLOCKS h) h
shaBlocks comp ptr nblocks =
  comp ptr nblocks >> updateLength nblocks

-- | The combinator `shaFinal` on an input compressor @comp@ gives
-- buffer action for the final chunk of data.
shaFinal :: (Primitive h, Storable h)
         => ShaBufferAction (BLOCKS h) h   -- ^ the raw compressor
         -> LengthWrite h                  -- ^ the length writer
         -> ShaBufferAction (BYTES Int) h
shaFinal comp lenW ptr msgLen = do
  updateLength msgLen
  totalBits <- extractLength
  let pad      = shaPad undefined msgLen $ lenW totalBits
      blocks   = atMost $ bytesToWrite pad
      in unsafeWrite pad ptr >> comp ptr blocks


-- | Padding is message followed by a single bit 1 and a glue of zeros
-- followed by the length so that the message is aligned to the block boundary.
shaPad :: IsSha h
       => h
       -> BYTES Int -- Message length
       -> ShaWrite h
       -> ShaWrite h
shaPad h msgLen = glueWrites 0 boundary hdr
  where skipMessage = skipWrite msgLen
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage <> oneBit
        boundary    = blocksOf 1 h



-- | Creates an implementation for a sha hash given the compressor and
-- the length writer.
shaImplementation :: IsSha h
                  => String                   -- ^ Name
                  -> String                   -- ^ Description
                  -> Compressor
                  -> LengthWrite h
                  -> HashI h (HashMemory h)
shaImplementation nam des comp lenW
  = HashI { hashIName               = nam
          , hashIDescription        = des
          , compress                = shaBlocks shaComp
          , compressFinal           = shaFinal  shaComp lenW
          , compressStartAlignment  = inBytes (1 :: ALIGN)
          }
  where shaComp = liftCompressor comp

{-# INLINE shaImplementation #-}
{-# INLINE portableC         #-}
portableC :: ( Primitive h
             , Storable h
             , Initialisable (HashMemory h) ()
             )
          => Compressor
          -> LengthWrite h
          -> HashI h (HashMemory h)
portableC = shaImplementation "portable-c-ffi"
            "Implementation using portable C and Haskell FFI"
