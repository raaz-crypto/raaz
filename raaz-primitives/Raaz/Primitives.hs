{-|

Generic cryptographic algorithms.

-}

{-# LANGUAGE TypeFamilies         #-}
module Raaz.Primitives
       ( BlockPrimitive(..)
       , Compressor(..)
       ) where

import Data.Word
import qualified Data.ByteString as B
import Data.ByteString.Internal (unsafeCreate)
import Foreign.Ptr(castPtr)

import Raaz.Types

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

class BlockPrimitive c => Compressor c where
  -- | The compress context.
  type Cxt c   :: *

  -- | Compresses blocks of data.
  compress :: c          -- ^ The compressor.
           -> Cxt c      -- ^ The current state.
           -> Word64     -- ^ Total blocks processed so far.
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
            -> Word64 -- ^ Length of the message in bytes
            -> Word64

  -- | This function gives the padding to add to the message.
  padding :: c              -- ^ The compressor
          -> Word64         -- ^ Length of the message in bytes.
          -> B.ByteString

  padding c len = unsafeCreate (fromIntegral $ padLength c len)
                               (unsafePadIt c len 0 . castPtr)

  -- | This is the unsafe version of the padding where it is assumed
  -- that the data buffer has enough space to accomodate the padding
  -- data.
  unsafePadIt :: c         -- ^ The compressor
              -> Word64    -- ^ the total length
              -> Int       -- ^ Byte position
              -> CryptoPtr -- ^ The buffer to put the padding
              -> IO ()

