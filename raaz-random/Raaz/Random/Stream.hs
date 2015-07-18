{- |

An abstraction for buffered random streams which can be generated from
`StreamGadget`s.

-}

{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}

module Raaz.Random.Stream
       ( RandomSource(..)
       , RandomPrim(..)
       , genBytes
       , genBytesNonZero
       ) where
import           Control.Monad                 (void)

import           Control.Applicative           ( (<*>) , (<$>) )
import qualified Data.ByteString               as BS
import           Data.ByteString.Internal      (ByteString, create)
import qualified Data.ByteString.Internal      as BS
import qualified Data.ByteString.Lazy          as BL
import qualified Data.ByteString.Lazy.Internal as BL
import           Foreign.ForeignPtr            (withForeignPtr)
import           Foreign.Ptr                   (castPtr, plusPtr)

import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString     as BU
import           Raaz.Core.Util.Ptr

-- | A buffered random source which uses a stream gadget as the
-- underlying source for generating random bytes.
data RandomSource g = RandomSource g
                                   (MemoryBuf (GadgetBuff g))
                                   (MemoryCell (BYTES Int))
                                   (MemoryCell (BYTES Int)) -- ^ Gadget, Buffer, Offset in Buffer, Bytes generated so far

-- | Primitive for Random Source
newtype RandomPrim p = RandomPrim p

memoryBufSize :: Bufferable b => MemoryBuf b -> BYTES Int
memoryBufSize mbuf = maxSizeOf $ getBufferable mbuf
  where getBufferable :: Bufferable b => MemoryBuf b -> b
        getBufferable _ = undefined

-- | Memory for random
zeroOutMemoryBuf :: Bufferable g => MemoryBuf g -> IO ()
zeroOutMemoryBuf buff = withMemoryBuf buff zeroMemory
{-# INLINE zeroOutMemoryBuf #-}

-- | Buffer for storing random data.
newtype GadgetBuff g = GadgetBuff g

instance Gadget g => Bufferable (GadgetBuff g) where
  maxSizeOf (GadgetBuff g) = atMost $ recommendedBlocks g

instance Primitive p => Primitive (RandomPrim p) where
  blockSize = blockSize . getPrim
    where
      getPrim :: RandomPrim p -> p
      getPrim _ = undefined

  type Key (RandomPrim p) = Key p

instance (Memory g, Gadget g) => Memory (RandomSource g) where
  memoryAlloc = RandomSource <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  underlyingPtr (RandomSource g _ _ _) = underlyingPtr g

instance (Memory g, Gadget g) => InitializableMemory (RandomSource g) where
  type IV (RandomSource g) = IV g
  initializeMemory (RandomSource g buffer celloffset cellcounter) iv = do
    initializeMemory g iv
    initializeMemory celloffset (memoryBufSize buffer)
    initializeMemory cellcounter 0
    zeroOutMemoryBuf buffer

instance StreamGadget g => Gadget (RandomSource g) where
  type PrimitiveOf (RandomSource g) = RandomPrim (PrimitiveOf g)

  apply rs blks cptr = void $ fillBytes (inBytes blks) rs cptr

instance StreamGadget g => StreamGadget (RandomSource g)

instance StreamGadget g => ByteSource (RandomSource g) where
  fillBytes nb rs@(RandomSource g buff celloffset cellcounter) cptr = do
    -- current offset in internal buffer
    offset <- cellPeek celloffset
    -- Fill location with random data and
    -- given offset in the internal buffer
    foffset <- go nb offset cptr
    -- update offset
    cellPoke celloffset foffset
    -- update counter
    cellModify cellcounter (+ nb)
    return $ Remaining rs
      where
        go !sz !offset !outptr
          -- Internal buffer already has required amount of random data so use it
          | netsz >= sz = do
            let action sz bfr = do
                  memcpy outptr (movePtr bfr offset) sz
                  return $ offset + sz
            withMemoryBuf buff action
         -- Internal buffer has less random data so use it and
         -- refill the buffer to use again
          | otherwise = do
              -- use random bytes of internal buffer and refill it
              withMemoryBuf buff doWithBuffer
              go (sz - netsz) 0 (movePtr outptr netsz)
                where
                  bsz = memoryBufSize buff
                  netsz = bsz - offset
                  doWithBuffer netsz bfr = memcpy outptr (movePtr bfr offset) netsz
                                      >> fillFromGadget g bsz bfr

-- | Applies the gadget on the given buffer. Note that this is valid
-- as the underlying gadget is `StreamGadget` and the `blockSize` is 1
-- BYTE. So this can be applied on any size of memory location.
fillFromGadget :: StreamGadget g => g -> BYTES Int -> CryptoPtr -> IO ()
fillFromGadget g bsz bfr = do
  -- Zero out the memory
  zeroMemory bsz bfr
  -- Refill buffer
  apply g (atMost bsz) bfr

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
                let nonzero = BS.filter (/=0x00) b      -- Remove null bytes
                go (BU.length nonzero + m) (nonzero:xs) -- Recurse to generate remaining bytes

-- | Converts `BL.ByteString` to `BS.ByteString`.
toStrict :: BL.ByteString -> BS.ByteString
#if MIN_VERSION_bytestring(0,10,0)
toStrict = BL.toStrict
#else
toStrict BL.Empty              = BS.empty
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

-- | Zero out given number of bytes in the memory location.
zeroMemory :: BYTES Int -> CryptoPtr -> IO ()
zeroMemory n cptr = memset cptr 0 n
