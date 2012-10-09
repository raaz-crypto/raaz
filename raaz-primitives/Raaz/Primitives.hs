{-|

Generic cryptographic algorithms.

-}

{-# LANGUAGE TypeFamilies         #-}
module Raaz.Primitives
       ( BlockPrimitive(..)
       , Compressor(..)
       , compressByteString
       , compressLazyByteString
       ) where

import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Internal (unsafeCreate)
import Foreign.Ptr(castPtr)
import Foreign.Marshal.Alloc(allocaBytes)

import Raaz.Types
import Raaz.Util.ByteString(fillUp)

-- | Abstraction that captures crypto primitives that work one block
-- at a time. Examples are block ciphers, Merkle-Damgård hashes etc.
class BlockPrimitive p where
  blockSize :: p -> Int -- ^ Block size in bytes

-- | A compressor is a crypto primitive that shrinks an arbitrary
-- sized string to a fixed size string. A message is usually padded
-- using some strategy. The obvious need for padding is to handle
-- messages that do not have a length that is a multiple of the block
-- length. Besides the security of certain primitives like the
-- Merkle-Damgård hashes depend on the padding.
--
-- [Note on message lengths:] All message lengths are in bits as
-- hashing schemes like the Merkle-Damgård and HAIFA use the number of
-- bits for strengthening etc. Besides it is easy to compute the
-- number of bytes (if required) from this parameter.

class BlockPrimitive c => Compressor c where
  -- | The compress context.
  type Cxt c   :: *

  -- | Compresses blocks of data.
  compress :: c          -- ^ The compressor.
           -> Cxt c      -- ^ The current state.
           -> Word64     -- ^ Number of bits processed so far
           -> CryptoPtr  -- ^ Data buffer containing the next block.
                         -- Implementations should ensure that the data
                         -- is undisturbed.
           -> Int        -- ^ Number of blocks at the above location.
           -> IO (Cxt c)

  -- | Although the compressor works one block at a time, handling the
  -- last block of data requires additional blocks mainly to handle
  -- padding. This variable gives the number of additional blocks
  -- required to handle this. In a hashing algorithm like sha this is
  -- 1 (this the the additional block and does not count the partially
  -- filled block if there is any).
  maxAdditionalBlocks :: c -> Int

  -- | The length of the padding message for a given length.
  padLength :: c      -- ^ The compressor
            -> Word64 -- ^ Length of the message in bits.
            -> Word64

  -- | This function gives the padding to add to the message.
  padding :: c              -- ^ The compressor
          -> Word64         -- ^ Length of the message in bits.
          -> B.ByteString

  padding c len = unsafeCreate (fromIntegral $ padLength c len)
                               (unsafePadIt c len 0 . castPtr)

  -- | This is the unsafe version of the padding where it is assumed
  -- that the data buffer has enough space to accomodate the padding
  -- data.
  unsafePadIt :: c         -- ^ The compressor
              -> Word64    -- ^ the length of the message in bits
              -> Int       -- ^ Byte position to start padding.
              -> CryptoPtr -- ^ The buffer to put the padding
              -> IO ()

-- | Compress a strict bytestring.
compressByteString :: Compressor c
                   => c             -- ^ The compressor
                   -> Cxt c         -- ^ The starting context
                   -> B.ByteString  -- ^ The input bytestring
                   -> IO (Cxt c)
compressByteString c cxt bs = compressChunks c cxt [bs]

-- | Compress a lazy bytestring.
compressLazyByteString :: Compressor c
                       => c            -- ^ The compressor
                       -> Cxt c        -- ^ the starting context
                       -> L.ByteString -- ^ the input bytestring
                       -> IO (Cxt c)
compressLazyByteString c cxt = compressChunks c cxt . L.toChunks

compressChunks :: Compressor c
               => c
               -> Cxt c
               -> [B.ByteString]
               -> IO (Cxt c)

compressChunks c context chunks = allocaBytes sz (go context 0 0 chunks)
    where sz    = blkSz * (maxAdditionalBlocks c + 1)
          blkSz = blockSize c
          go cxt tsize r [] cptr = do
                 unsafePadIt c  l (fromIntegral r) cptr
                 compress c cxt l cptr blks
             where l      = tsize + r * 8
                   pl     = padLength c l
                   blks   = fromIntegral (l + pl) `quot` blkSz
          go cxt tsize r (b:bs) cptr = do
                 erem <- fillUp blkSz cptr (fromIntegral r) b
                 case erem of
                      Left  r' -> go cxt tsize (fromIntegral r') bs cptr
                      Right b' -> do cxt' <- compress c cxt tsize cptr 1
                                     go cxt' tsize' 0 (b':bs) cptr

             where tsize' = tsize + fromIntegral (blkSz * 8)
