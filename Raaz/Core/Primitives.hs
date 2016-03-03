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
{-# LANGUAGE DefaultSignatures           #-}
{-# LANGUAGE CPP                         #-}
{-# LANGUAGE ConstraintKinds             #-}
{-# LANGUAGE ExistentialQuantification   #-}

module Raaz.Core.Primitives
       ( -- * Primtives and their implementations.
         Primitive(..), Symmetric(..), Asymmetric(..)
       , BLOCKS, blocksOf
       ) where

import Raaz.Core.Types
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
-- There is a /reference implementation/ where the emphasis is on
-- correctness rather than speed or security. They are used to verify
-- the correctness of the other implementations for the same
-- primitive. Apart from this, for production use, we have a
-- recommended implementation.
class (Describable (Implementation p)) => Primitive p where

  -- | The block size.
  blockSize :: p -> BYTES Int

  -- | Associated type that captures an implementation of this
  -- primitive.
  type Implementation p :: *

  -- | The recommended implementation for the primitive.
  recommended :: p -> Implementation p

-- | A symmetric primitive. An example would be primitives like
-- Ciphers, HMACs etc.
class Primitive prim => Symmetric prim where

  -- | The key for the primitive.
  type Key prim

-- | An asymmetric primitive.
class Asymmetric prim where

  -- | The public key
  type PublicKey prim

  -- | The private key
  type PrivateKey prim


------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
newtype BLOCKS p = BLOCKS Int
                 deriving (Show, Eq, Ord, Enum, Real, Num, Integral)

instance Primitive p => LengthUnit (BLOCKS p) where
  inBytes p@(BLOCKS x) = scale * blockSize (getPrimitiveType p)
    where scale = BYTES x
          getPrimitiveType :: BLOCKS p -> p
          getPrimitiveType _ = undefined

-- | The expression @n `blocksOf` p@ specifies the message lengths in
-- units of the block length of the primitive @p@. This expression is
-- sometimes required to make the type checker happy.
blocksOf :: Primitive p =>  Int -> p -> BLOCKS p
blocksOf n _ = BLOCKS n
