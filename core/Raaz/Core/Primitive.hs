-- |
--
-- Module      : Raaz.Core.Primitive
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE DataKinds                   #-}

module Raaz.Core.Primitive
       ( -- * Cryptographic Primtives
         Primitive(..), Key, Nounce, Block, BlockPtr, AlignedBlockPtr
       , BlockCount(..), blocksOf
       ) where

import Data.Vector.Unboxed (Unbox)
import GHC.TypeLits
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

class ( Unbox (WordType p)
      , EndianStore (WordType p)
      , KnownNat (WordsPerBlock p)
      ) => Primitive p where

  -- | The block which is the smallest unit of data that the primitive
  -- processes, is typically considered as an array of a particular
  -- word which is captured by the following associated type.
  type WordType p :: *

  -- | The size of the array that forms the block. In particular, the
  -- block can be seen as an array of size `BlockArraySize p` of type
  -- `WORD p`.
  type WordsPerBlock p :: Nat

-- | The type family that captures the key of a keyed primitive.
data family Key p :: *

-- | In addition to keys, certain primitives require nounces that can
-- be public but needs to be distinct across different uses when
-- sharing the key. The type family that captures the nounce for a
-- primitive (if it requires one).
data family Nounce p :: *

-- | A block of the primitive.
type Block p   = Tuple (WordsPerBlock p) (WordType p)

-- | Pointer to a block of the primitive.
type BlockPtr p = Ptr (Block p)

-- | Aligned version of block pointers.

type AlignedBlockPtr n p = AlignedPtr n (Block p)


------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BlockCount`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
newtype BlockCount p = BlockCount {unBlockCount :: Int}
                     deriving (Show, Eq, Ord, Enum, Storable)

instance Semigroup (BlockCount p) where
  (<>) x y = BlockCount $ unBlockCount x + unBlockCount y
instance Monoid (BlockCount p) where
  mempty   = BlockCount 0
  mappend  = (<>)


instance Primitive p => LengthUnit (BlockCount p) where
  inBytes p@(BlockCount x) = toEnum x * nWords p * wordSize p
    where wordSize = sizeOf . proxyWT
          nWords   = toEnum . fromEnum . natVal . proxyWPB
          proxyWT :: Primitive p => BlockCount p -> Proxy (WordType p)
          proxyWT  = const Proxy
          proxyWPB   :: Primitive p => BlockCount p -> Proxy (WordsPerBlock p)
          proxyWPB = const Proxy


-- | The expression @n `blocksOf` primProxy@ specifies the message
-- lengths in units of the block length of the primitive whose proxy
-- is @primProxy@. This expression is sometimes required to make the
-- type checker happy.
blocksOf :: Int -> Proxy p -> BlockCount p
blocksOf n _ = BlockCount n
