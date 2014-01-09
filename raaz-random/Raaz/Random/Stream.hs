{-

An abstraction for buffered and unbuffered streams which can be
generated from `StreamGadget`s.

-}

{-# LANGUAGE BangPatterns          #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module Raaz.Random.Stream
       ( RandomSource(..)
       , fromGadget
       ) where

import           Prelude                  hiding (length)

import           Raaz.ByteSource
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.Ptr

-- | A buffered random source which uses a stream gadget as the
-- underlying source for generating random bytes.
data RandomSource g = RandomSource g                         -- ^ Gadget
                                   Buffer                    -- ^ Underlying Buffer
                                   (CryptoCell (BYTES Int))  -- ^ Offset in Buffer
                                   (CryptoCell (BYTES Int))  -- ^ `BYTES` generated so far

-- | Represents a buffer.
data Buffer = Buffer { bufferLoc  :: CryptoPtr  -- ^ Starting Location
                     , bufferSize :: BYTES Int  -- ^ Size
                     }

createBuffer :: BYTES Int -> IO Buffer
createBuffer size = do
  cptr <- mallocBuffer size
  return (Buffer cptr size)

emptyBuffer :: Buffer -> IO ()
emptyBuffer (Buffer cptr size) = memset cptr 0 size

-- | Create a `RandomSource` from a `StreamGadget`.
fromGadget :: StreamGadget g
           => g                        -- ^ Gadget
           -> BLOCKS (PrimitiveOf g)   -- ^ Buffer Size
           -> IO (RandomSource g)
fromGadget g size = do
  buffer <- createBuffer (cryptoCoerce size)
  offset <- newMemory
  counter <- newMemory
  cellStore offset (cryptoCoerce size)
  cellStore counter 0
  return (RandomSource g buffer offset counter)

instance Primitive p => Primitive (RandomSource p) where
  blockSize = blockSize . getPrim
    where
      getPrim :: RandomSource p -> p
      getPrim _ = undefined
  newtype IV (RandomSource p) = RSIV (IV p)

instance Initializable p => Initializable (RandomSource p) where
  ivSize rs = ivSize (getPrim rs)
    where
      getPrim :: (RandomSource p) -> p
      getPrim _ = undefined
  getIV bs = RSIV (getIV bs)

instance StreamGadget g => Gadget (RandomSource g) where
  type PrimitiveOf (RandomSource g) = RandomSource (PrimitiveOf g)
  type MemoryOf (RandomSource g) = MemoryOf g
  -- | Uses the buffer of recommended block size.
  newGadgetWithMemory gmem = do
    g <- newGadgetWithMemory gmem
    celloffset <- newMemory
    cellcounter <- newMemory
    buffer <- createBuffer $ cryptoCoerce $ recommendedBlocks g
    return $ RandomSource g buffer celloffset cellcounter
  initialize (RandomSource g buffer celloffset cellcounter) (RSIV iv) = do
    initialize g iv
    emptyBuffer buffer
    cellStore celloffset (bufferSize buffer)
    cellStore cellcounter 0
  -- | Finalize is of no use for a random number generator.
  finalize (RandomSource g buffer celloffset cellcounter) = do
    p <- finalize g
    return (RandomSource p buffer celloffset cellcounter)
  apply rs blks cptr = fillBytes (cryptoCoerce blks) rs cptr >> return ()

instance StreamGadget g => ByteSource (RandomSource g) where
  fillBytes nb rs@(RandomSource g (Buffer bfr bsz) celloffset cellcounter) cptr = do
    offset <- cellLoad celloffset
    foffset <- go nb offset cptr
    cellStore celloffset foffset
    cellModify cellcounter (+ nb)
    return $ Remaining rs
      where
        go !sz !offst !outptr
          | netsz >= sz = memcpy outptr (movePtr bfr offst) sz >> return (offst + sz)
          | otherwise = do
              memcpy outptr (movePtr bfr offst) netsz
              fillFromGadget g bsz bfr
              go (sz - netsz) 0 (movePtr outptr netsz)
                where
                  netsz = bsz - offst

fillFromGadget :: Gadget g => g -> BYTES Int -> CryptoPtr -> IO ()
fillFromGadget g bsz bfr = do
  -- Zero out the memory
  memset bfr 0 bsz
  -- Refill buffer
  apply g (cryptoCoerce nblks) bfr
    where
      getPrim :: (Gadget g) => g -> PrimitiveOf g
      getPrim _ = undefined
      gadblksz :: BYTES Int
      gadblksz = blockSize (getPrim g)
      nblks  = bsz `quot` gadblksz
