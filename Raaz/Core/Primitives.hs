{-|

Generic cryptographic block primtives and their implementations. This
module exposes low-level generic code used in the raaz system. Most
likely, one would not need to stoop so low and it might be better to
use a more high level interface.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE CPP                         #-}
{-# LANGUAGE ConstraintKinds             #-}
{-# LANGUAGE ExistentialQuantification   #-}
{-# LANGUAGE DataKinds                   #-}

module Raaz.Core.Primitives
       ( -- * Primtives and their implementations.
         Primitive(..), BlockAlgorithm(..), Recommendation(..), blockSize
       , BLOCKS, blocksOf
       , allocBufferFor
       , Symmetric(..)
       ) where

import Data.Monoid
import Data.Proxy
import GHC.TypeLits
import Prelude

import Raaz.Core.Types

-- | Implementation of block primitives work on buffers. Often for optimal
-- performance, and in some case for safety, we need restrictions on
-- the size and alignment of the buffer pointer. This type class
-- captures such restrictions.
class Describable a => BlockAlgorithm a where

  -- | The alignment expected for the buffer pointer.
  bufferStartAlignment :: a -> Alignment


----------------------- A primitive ------------------------------------


-- | The type class that captures an abstract block cryptographic
-- primitive. Bulk cryptographic primitives like hashes, ciphers etc
-- often acts on blocks of data. The size of the block is captured by
-- the member `blockSize`.
--
-- As a library, raaz believes in providing multiple implementations
-- for a given primitive. The associated type `Implementation`
-- captures implementations of the primitive.
--
-- For use in production code, the library recommends a particular
-- implementation using the `Recommendation` class. By default this is
-- the implementation used when no explicit implementation is
-- specified.
class ( BlockAlgorithm (Implementation p)
      , KnownNat (BlockSize p)
      )
      => Primitive p where

  type BlockSize p :: Nat

  -- | Associated type that captures an implementation of this
  -- primitive.
  type Implementation p :: *


-- | The block size.
blockSize :: Primitive prim => Proxy prim -> BYTES Int
blockSize  = toEnum . fromEnum . natVal . getBlockSizeProxy
  where getBlockSizeProxy ::  Proxy prim -> Proxy (BlockSize prim)
        getBlockSizeProxy _ = Proxy

-- | Primitives that have a recommended implementations.
class Primitive p => Recommendation p where
  -- | The recommended implementation for the primitive.
  recommended :: Proxy p -> Implementation p

-- | Allocate a buffer a particular implementation of a primitive prim.
-- algorithm @algo@. It ensures that the memory passed is aligned
-- according to the demands of the implementation.
allocBufferFor :: Primitive prim
               => Implementation prim
               -> BLOCKS prim
               -> (Pointer -> IO b)
               -> IO b
allocBufferFor imp  = allocaAligned $ bufferStartAlignment imp

-- | Block primitives that are symmetric key algorithms
class Primitive prim => Symmetric prim where
  type Key prim :: *

------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
newtype BLOCKS p = BLOCKS {unBLOCKS :: Int}
                 deriving (Show, Eq, Ord, Enum)

instance Monoid (BLOCKS p) where
  mempty      = BLOCKS 0
  mappend x y = BLOCKS $ unBLOCKS x + unBLOCKS y

instance Primitive p => LengthUnit (BLOCKS p) where
  inBytes p@(BLOCKS x) = scale * blockSize primProxy
    where scale = BYTES x
          primProxy = getProxy p
          getProxy :: BLOCKS p -> Proxy p
          getProxy _ = Proxy

-- | The expression @n `blocksOf` p@ specifies the message lengths in
-- units of the block length of the primitive @p@. This expression is
-- sometimes required to make the type checker happy.
blocksOf :: Int -> Proxy p -> BLOCKS p
blocksOf n _ = BLOCKS n
