{-|

Generic cryptographic algorithms.

-}

{-# LANGUAGE TypeFamilies         #-}
module Raaz.Primitives
       ( BlockPrimitive(..)
       , Compressor(..)
       ) where

import Data.Word

import Raaz.Types

-- | Abstraction that captures crypto primitives that work one block
-- at a time. Examples are block ciphers, Merkle-Damgård hashes etc.
class BlockPrimitive p where
  blockSize :: p -> Int -- ^ Block size in bytes

-- | A compressor is a crypto primitive that shrinks an arbitrary
-- sized string to a fixed size string.
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
