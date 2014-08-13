{-|

This module defines the hash instances for blake256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Blake256.Instance () where

import Control.Monad       ( foldM )
import Data.Default()
import Data.Word

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Blake256.Type
import Raaz.Hash.Blake256.Ref
import Raaz.Hash.Blake256.CPortable()

----------------------------- BLAKE256 -------------------------------------------

instance CryptoPrimitive BLAKE256 where
  type Recommended BLAKE256 = CGadget BLAKE256
  type Reference BLAKE256 = HGadget BLAKE256

instance Hash BLAKE256

instance Gadget (HGadget BLAKE256) where
  type PrimitiveOf (HGadget BLAKE256) = BLAKE256
  type MemoryOf (HGadget BLAKE256) = (CryptoCell BLAKE256, CryptoCell Salt, CryptoCell (BITS Word64))
  newGadgetWithMemory = return . HGadget

  initialize (HGadget (cellBlake, cellSalt, cellCounter)) (BLAKE256Cxt blake salt counter) = do
    cellPoke cellSalt salt
    cellPoke cellBlake blake
    cellPoke cellCounter counter

  finalize (HGadget (cellBlake, cellSalt, cellCounter)) = do
    b <- cellPeek cellBlake
    s <- cellPeek cellSalt
    c <- cellPeek cellCounter
    return $ BLAKE256Cxt b s c

  apply (HGadget (cellBlake, cellSalt, cellCounter)) n cptr = do
    initial                <- cellPeek cellBlake
    salt                   <- cellPeek cellSalt
    counter                <- cellPeek cellCounter
    (final, nCounter , _ ) <- foldM (moveAndHash salt) (initial, counter, cptr) [1..n]
    cellPoke cellBlake final
    cellPoke cellCounter nCounter
    where
      sz = blockSize (undefined :: BLAKE256)
      moveAndHash salt (cxt, counter, ptr) _ = do
        let nCounter = counter + inBits sz
        newCxt       <- blake256CompressSingle cxt salt nCounter ptr
        return (newCxt, nCounter, ptr `movePtr` sz)

instance PaddableGadget (HGadget BLAKE256) where
  unsafeApplyLast g@(HGadget (_, _, cellCounter)) blocks bytes cptr = do
    let bits      = inBits bytes :: BITS Word64
        len       = inBits blocks + bits
        p         = primitiveOf g
        block     = blockSize p
        padl      = padLength p len
        padBlocks = atMost padl `asTypeOf` blocks
        tBlocks   = atLeast (bytes + padl)
        callApply pblocks
          | pblocks == 0 = do
                             apply g (tBlocks-1) cptr
                             cellModify cellCounter (\a -> a - inBits padl)
                             apply g 1 (cptr `movePtr` (tBlocks - 1))
          | otherwise    = do
                             apply g (tBlocks-2) cptr
                             cellModify cellCounter (\a -> a - inBits (padl - block))
                             apply g 1 (cptr `movePtr` (tBlocks-2))
                             cellPoke cellCounter 0
                             apply g 1 (cptr `movePtr` (tBlocks-1))

    unsafePad p len (cptr `movePtr` bytes)
    callApply padBlocks
