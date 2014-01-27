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

import Control.Monad            (void)

import Raaz.ByteSource
import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr

-- | A buffered random source which uses a stream gadget as the
-- underlying source for generating random bytes.
data RandomSource g = RandomSource g                         -- ^ Gadget
                                   (Buffer (GadgetBuff g))   -- ^ Underlying Buffer
                                   (CryptoCell (BYTES Int))  -- ^ Offset in Buffer
                                   (CryptoCell (BYTES Int))  -- ^ `BYTES` generated so far

-- | Primitive for Random Source
newtype RandomPrim p = RandomPrim p

zeroOutBuffer :: Buffer g -> IO ()
zeroOutBuffer buff = withBuffer buff (\cptr -> memset cptr 0 (bufferSize buff))

newtype GadgetBuff g = GadgetBuff g

instance (Gadget g) => Bufferable (GadgetBuff g) where
  sizeOfBuffer (GadgetBuff g) = fromIntegral $ recommendedBlocks g

-- | Create a `RandomSource` from a `StreamGadget`.
fromGadget :: StreamGadget g
           => g                        -- ^ Gadget
           -> IO (RandomSource g)
fromGadget g = do
  buffer <- newMemory
  offset <- newMemory
  counter <- newMemory
  cellStore offset (bufferSize buffer)
  cellStore counter 0
  return (RandomSource g buffer offset counter)

instance Primitive p => Primitive (RandomPrim p) where
  blockSize = blockSize . getPrim
    where
      getPrim :: RandomPrim p -> p
      getPrim _ = undefined
  newtype IV (RandomPrim p) = RSIV (IV p)

instance Initializable p => Initializable (RandomPrim p) where
  ivSize rs = ivSize (getPrim rs)
    where
      getPrim :: RandomPrim p -> p
      getPrim _ = undefined
  getIV bs = RSIV (getIV bs)

instance StreamGadget g => Gadget (RandomSource g) where
  type PrimitiveOf (RandomSource g) = RandomPrim (PrimitiveOf g)
  type MemoryOf (RandomSource g) = (MemoryOf g, Buffer (GadgetBuff g))
  -- | Uses the buffer of recommended block size.
  newGadgetWithMemory (gmem,buffer) = do
    g <- newGadgetWithMemory gmem
    celloffset <- newMemory
    cellcounter <- newMemory
    return $ RandomSource g buffer celloffset cellcounter
  initialize (RandomSource g buffer celloffset cellcounter) (RSIV iv) = do
    initialize g iv
    zeroOutBuffer buffer
    cellStore celloffset (bufferSize buffer)
    cellStore cellcounter 0
  -- | Finalize is of no use for a random number generator.
  finalize (RandomSource g _ _ _) = do
    p <- finalize g
    return (RandomPrim p)
  apply rs blks cptr = void $ fillBytes (cryptoCoerce blks) rs cptr

instance StreamGadget g => ByteSource (RandomSource g) where
  fillBytes nb rs@(RandomSource g buff celloffset cellcounter) cptr = do
    offset <- cellLoad celloffset
    foffset <- go nb offset cptr
    cellStore celloffset foffset
    cellModify cellcounter (+ nb)
    return $ Remaining rs
      where
        go !sz !offst !outptr
          | netsz >= sz = withBuffer buff (\bfr -> memcpy outptr (movePtr bfr offst) sz >> return (offst + sz))
          | otherwise = do
              withBuffer buff doWithBuffer
              go (sz - netsz) 0 (movePtr outptr netsz)
                where
                  bsz = bufferSize buff
                  netsz = bsz - offst
                  doWithBuffer bfr = memcpy outptr (movePtr bfr offst) netsz
                                  >> fillFromGadget g bsz bfr

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
