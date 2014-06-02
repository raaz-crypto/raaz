{- |

An abstraction for buffered and unbuffered streams which can be
generated from `StreamGadget`s.

-}

{-# LANGUAGE CPP                   #-}
{-# LANGUAGE BangPatterns          #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module Raaz.Random.Stream
       ( RandomSource(..)
       , RandomPrim(..)
       , fromGadget
       , genBytes
       , genBytesNonZero
       , Cxt(RSCxt)
       ) where
import           Control.Applicative
import           Control.Monad                 ( void               )


import           Data.ByteString.Internal      ( ByteString, create )
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Internal      as BS
import qualified Data.ByteString.Lazy          as BL
import qualified Data.ByteString.Lazy.Internal as BL
import           Foreign.ForeignPtr            ( withForeignPtr     )
import           Foreign.Ptr                   ( castPtr, plusPtr   )

import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr
import qualified Raaz.Core.Util.ByteString     as BU

-- | A buffered random source which uses a stream gadget as the
-- underlying source for generating random bytes.
data RandomSource g = RandomSource g
                                   (MemoryBuf (GadgetBuff g))
                                   (CryptoCell (BYTES Int))
                                   (CryptoCell (BYTES Int)) -- ^ Gadget, Buffer, Offset in Buffer, Bytes generated so far

-- | Primitive for Random Source
newtype RandomPrim p = RandomPrim p

zeroOutMemoryBuf :: MemoryBuf g -> IO ()
zeroOutMemoryBuf buff = withMemoryBuf buff (\cptr -> memset cptr 0 (memoryBufSize buff))

-- | Buffer for storing random data.
newtype GadgetBuff g = GadgetBuff g

instance (Gadget g) => Bufferable (GadgetBuff g) where
  maxSizeOf (GadgetBuff g) = roundFloor $ recommendedBlocks g

-- | Create a `RandomSource` from a `StreamGadget`.
fromGadget :: StreamGadget g
           => g                        -- ^ Gadget
           -> IO (RandomSource g)
fromGadget g = do
  buffer <- newMemory
  offset <- newMemory
  counter <- newMemory
  cellStore offset (memoryBufSize buffer)
  cellStore counter 0
  return (RandomSource g buffer offset counter)

instance Primitive p => Primitive (RandomPrim p) where
  blockSize = blockSize . getPrim
    where
      getPrim :: RandomPrim p -> p
      getPrim _ = undefined
  newtype Cxt (RandomPrim p) = RSCxt (Cxt p)

instance StreamGadget g => Gadget (RandomSource g) where
  type PrimitiveOf (RandomSource g) = RandomPrim (PrimitiveOf g)
  type MemoryOf (RandomSource g) = ( MemoryOf g
                                   , MemoryBuf (GadgetBuff g)
                                   , CryptoCell (BYTES Int)
                                   , CryptoCell (BYTES Int)
                                   )
  -- | Uses the buffer of recommended block size.
  newGadgetWithMemory (gmem,buffer,celloffset,cellcounter) = do
    g <- newGadgetWithMemory gmem
    cellStore celloffset (memoryBufSize buffer)
    cellStore cellcounter 0
    return $ RandomSource g buffer celloffset cellcounter
  initialize (RandomSource g buffer celloffset cellcounter) (RSCxt iv) = do
    initialize g iv
    zeroOutMemoryBuf buffer
    cellStore celloffset (memoryBufSize buffer)
    cellStore cellcounter 0
  -- | Finalize is of no use for a random number generator.
  finalize (RandomSource g _ _ _) = RSCxt <$> finalize g
  apply rs blks cptr = void $ fillBytes (roundFloor blks) rs cptr

instance StreamGadget g => ByteSource (RandomSource g) where
  fillBytes nb rs@(RandomSource g buff celloffset cellcounter) cptr = do
    offset <- cellLoad celloffset
    foffset <- go nb offset cptr
    cellStore celloffset foffset
    cellModify cellcounter (+ nb)
    return $ Remaining rs
      where
        go !sz !offst !outptr
          | netsz >= sz = withMemoryBuf buff (\bfr -> memcpy outptr (movePtr bfr offst) sz >> return (offst + sz))
          | otherwise = do
              withMemoryBuf buff doWithBuffer
              go (sz - netsz) 0 (movePtr outptr netsz)
                where
                  bsz = memoryBufSize buff
                  netsz = bsz - offst
                  doWithBuffer bfr = memcpy outptr (movePtr bfr offst) netsz
                                  >> fillFromGadget g bsz bfr

fillFromGadget :: Gadget g => g -> BYTES Int -> CryptoPtr -> IO ()
fillFromGadget g bsz bfr = do
  -- Zero out the memory
  memset bfr 0 bsz
  -- Refill buffer
  apply g (roundFloor nblks) bfr
    where
      getPrim :: (Gadget g) => g -> PrimitiveOf g
      getPrim _ = undefined
      gadblksz :: BYTES Int
      gadblksz = blockSize (getPrim g)
      nblks  = bsz `quot` gadblksz

-- | Generates given number of random bytes.
genBytes :: StreamGadget g => RandomSource g -> BYTES Int -> IO ByteString
genBytes src n = create (fromIntegral n) (fillFromGadget src n . castPtr)

-- | Generates given number of nonzero random bytes.
genBytesNonZero :: StreamGadget g => RandomSource g -> BYTES Int -> IO ByteString
genBytesNonZero src n = go 0 []
  where
    go !m !xs | m >= n = return $ BS.take (fromIntegral n) $ toStrict $ BL.fromChunks xs
              | otherwise = do
                b <- genBytes src (n-m)
                let nonzero = BS.filter (/=0x00) b
                go (BU.length nonzero + m) (nonzero:xs)

-- | Converts `BL.ByteString` to `BS.ByteString`.
toStrict :: BL.ByteString -> BS.ByteString
#if MIN_VERSION_bytestring(0,10,0)
toStrict = BL.toStrict
#else
toStrict BL.Empty           = BS.empty
toStrict (BL.Chunk c BL.Empty) = c
toStrict cs0 = BS.unsafeCreate totalLen $ \ptr -> go cs0 ptr
  where
    totalLen = BL.foldlChunks (\a c -> a + BS.length c) 0 cs0

    go BL.Empty                         !_       = return ()
    go (BL.Chunk (BS.PS fp off len) cs) !destptr =
      withForeignPtr fp $ \p -> do
        BS.memcpy destptr (p `plusPtr` off) (fromIntegral len)
        go cs (destptr `plusPtr` len)
#endif
