{-|

Generic cryptographic block primtives and their implementations. This
module exposes low-level generic code used in the raaz system. Most
likely, one would not need to stoop so low and it might be better to
use a more high level interface.

-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE DataKinds                   #-}

module Raaz.Core.Primitive
       ( -- * Cryptographic Primtives
         Primitive(..), Key, Nounce, Block, BlockPtr
       , BLOCKS(..), blocksOf
       ) where

import GHC.TypeLits

import Foreign.Ptr      ( Ptr      )
import Foreign.Storable ( Storable )
import Raaz.Core.Prelude
import Raaz.Core.Types.Endian
import Raaz.Core.Types.Pointer
import Raaz.Core.Types.Tuple

----------------------- A primitive ------------------------------------


-- | Cryptographic primitives that process bulk data (like ciphers,
-- cryptographic hashes) process data in blocks. For data that is not
-- a multiple of the block size they may have some padding
-- strategy. The type class that captures an abstract block
-- cryptographic primitive.
--

class (EndianStore (WordType p), KnownNat (WordsPerBlock p)) => Primitive p where

  -- | The block which is the smallest unit of data that the primitive
  -- processes, is typically considered as an array of a particular
  -- word which is captured by the following associated type.
  type WordType p :: *

  -- | The size of the array that forms the block. In particular, the
  -- block can be seen as an array of size `BlockArraySize p` of type
  -- `WORD p`.
  type WordsPerBlock p :: Nat


-- type BlockPtr p = Ptr (Tuple (BlockArraySize p) (WORD p)

-- | The type family that captures the key of a keyed primitive.
data family Key p :: *

-- | In addition to keys, certain primitives require nounces that can
-- be public but needs to be distinct across different uses when
-- sharing the key. The type family that captures the nounce for a
-- primitive (if it requires one).
data family Nounce p :: *

type Block p   = Tuple (WordsPerBlock p) (WordType p)
-- | Pointer to a block of the primitive.
type BlockPtr p = Ptr (Block p)

