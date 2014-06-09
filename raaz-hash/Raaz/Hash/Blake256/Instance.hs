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

----------------------------- BLAKE256 -------------------------------------------

instance CryptoPrimitive BLAKE256 where
  type Recommended BLAKE256 = HGadget BLAKE256
  type Reference BLAKE256 = HGadget BLAKE256

instance Hash BLAKE256

instance Gadget (HGadget BLAKE256) where
  type PrimitiveOf (HGadget BLAKE256) = BLAKE256
  type MemoryOf (HGadget BLAKE256) = (CryptoCell BLAKE256, CryptoCell Salt, CryptoCell (BITS Word64))
  newGadgetWithMemory = return . HGadget
  initialize (HGadget (cellBlake, cellSalt, cellCounter)) (BLAKE256Cxt blake salt counter) = do
    cellStore cellSalt salt
    cellStore cellBlake blake
    cellStore cellCounter counter
  finalize (HGadget (cellBlake, cellSalt, cellCounter)) = do
    b <- cellLoad cellBlake
    s <- cellLoad cellSalt
    c <- cellLoad cellCounter
    return $ BLAKE256Cxt b s c
  apply (HGadget (cellBlake, cellSalt, cellCounter)) n cptr = do
    initial <- cellLoad cellBlake
    salt <- cellLoad cellSalt
    counter <- cellLoad cellCounter
    (final, nCounter , _ )  <- foldM (moveAndHash salt) (initial, counter, cptr) [1..n]
    cellStore cellBlake final
    cellStore cellCounter nCounter
    where
      sz = blockSize (undefined :: BLAKE256)
      moveAndHash salt (cxt, counter, ptr) _ = do
        let nCounter = counter + roundFloor sz
        newCxt <- blake256CompressSingle cxt salt nCounter ptr
        return (newCxt, nCounter, ptr `movePtr` sz)

instance PaddableGadget (HGadget BLAKE256) where
	unsafeApplyLast g@(HGadget (_, _, cellCounter)) blocks bytes cptr = do
	  let bits = roundFloor bytes :: BITS Word64
	      len  = roundFloor blocks + bits
	      p = primitiveOf g
	      block = blockSize p
	      padl = padLength p len
	      padBlocks = roundFloor padl `asTypeOf` blocks
	      tBlocks = roundFloor (bytes + padl)
	  unsafePad p len (cptr `movePtr` bytes)
	  if padBlocks==0
		  then do
			apply g (tBlocks-1) cptr
			cellModify cellCounter (\a -> a - roundFloor padl)
			apply g 1 (cptr `movePtr` (tBlocks - 1))
		else do
			apply g (tBlocks-2) cptr
			cellModify cellCounter (\a -> a - roundFloor (padl - block))
			apply g 1 (cptr `movePtr` (tBlocks-2))
			cellStore cellCounter 0
			apply g 1 (cptr `movePtr` (tBlocks-1))
