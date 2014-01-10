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
import Foreign.ForeignPtr.Safe  ( finalizeForeignPtr
                                , mallocForeignPtrBytes
                                , withForeignPtr
                                )
import Foreign.Storable

import Raaz.ByteSource
import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.Ptr
import Raaz.Util.SecureMemory

-- | A buffered random source which uses a stream gadget as the
-- underlying source for generating random bytes.
data RandomSource g = RandomSource g                         -- ^ Gadget
                                   (Buffer g)                -- ^ Underlying Buffer
                                   (CryptoCell (BYTES Int))  -- ^ Offset in Buffer
                                   (CryptoCell (BYTES Int))  -- ^ `BYTES` generated so far

-- | Represents a buffer.
data Buffer g = Buffer (BYTES Int) ForeignCryptoPtr

bufferSize :: Buffer g -> BYTES Int
bufferSize (Buffer sz _) = sz

instance Gadget g => Memory (Buffer g) where
  newMemory = mal undefined
    where mal :: Gadget g => g -> IO (Buffer g)
          mal g = fmap (Buffer bsize) $ mallocForeignPtrBytes size
            where
              size = fromIntegral bsize
              bsize :: BYTES Int
              bsize = cryptoCoerce $ recommendedBlocks g
  freeMemory (Buffer _ fptr) = finalizeForeignPtr fptr
  copyMemory (Buffer sz sf) (Buffer _ df) = withForeignPtr sf do1
    where do1 sptr = withForeignPtr df (do2 sptr)
          do2 sptr dptr = memcpy dptr sptr (BYTES sz)
  withSecureMemory f bk = allocSec undefined bk >>= f
   where
     wordAlign :: BYTES Int -> BYTES Int
     wordAlign size | extra == 0 = size
                    | otherwise  = size + alignSize - extra
           where alignSize = fromIntegral $ sizeOf (undefined :: CryptoAlign)
                 extra = size `rem` alignSize
     allocSec :: Gadget g => g -> PoolRef -> IO (Buffer g)
     allocSec g pref = allocSecureMem (wordAlign size) pref
         >>= maybe (fail "SecureMemory Exhausted") (return . Buffer size)
       where
         size = cryptoCoerce $ recommendedBlocks g

zeroOutBuffer :: Buffer g -> IO ()
zeroOutBuffer (Buffer size fptr) = withForeignPtr fptr (\cptr -> memset cptr 0 size)

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

instance Primitive p => Primitive (RandomSource p) where
  blockSize = blockSize . getPrim
    where
      getPrim :: RandomSource p -> p
      getPrim _ = undefined
  newtype IV (RandomSource p) = RSIV (IV p)

instance Initializable p => Initializable (RandomSource p) where
  ivSize rs = ivSize (getPrim rs)
    where
      getPrim :: RandomSource p -> p
      getPrim _ = undefined
  getIV bs = RSIV (getIV bs)

instance StreamGadget g => Gadget (RandomSource g) where
  type PrimitiveOf (RandomSource g) = RandomSource (PrimitiveOf g)
  type MemoryOf (RandomSource g) = (MemoryOf g, Buffer g)
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
  finalize (RandomSource g (Buffer fptr sz) celloffset cellcounter) = do
    p <- finalize g
    return (RandomSource p (Buffer fptr sz) celloffset cellcounter)
  apply rs blks cptr = void $ fillBytes (cryptoCoerce blks) rs cptr

instance StreamGadget g => ByteSource (RandomSource g) where
  fillBytes nb rs@(RandomSource g (Buffer bsz fptr) celloffset cellcounter) cptr = do
    offset <- cellLoad celloffset
    foffset <- go nb offset cptr
    cellStore celloffset foffset
    cellModify cellcounter (+ nb)
    return $ Remaining rs
      where
        go !sz !offst !outptr
          | netsz >= sz = withForeignPtr fptr (\bfr -> memcpy outptr (movePtr bfr offst) sz >> return (offst + sz))
          | otherwise = do
              withForeignPtr fptr doWithBuffer
              go (sz - netsz) 0 (movePtr outptr netsz)
                where
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
