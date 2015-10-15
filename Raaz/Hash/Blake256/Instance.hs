{-|

This module defines the hash instances for blake256 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Blake256.Instance () where

import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU
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
  type Recommended BLAKE256 = CGadgetBlake256
  type Reference BLAKE256 = HGadgetBlake256

instance Hash BLAKE256 where
  defaultKey _ = (blake, salt)
    where salt  = Salt $ VU.fromList [0,0,0,0]
          blake = BLAKE256 $ VU.fromList [ 0x6a09e667
                                         , 0xbb67ae85
                                         , 0x3c6ef372
                                         , 0xa54ff53a
                                         , 0x510e527f
                                         , 0x9b05688c
                                         , 0x1f83d9ab
                                         , 0x5be0cd19
                                         ]

  hashDigest = fst

instance InitializableMemory HGadgetBlake256 where
  type IV HGadgetBlake256 = (BLAKE256, Salt)

  initializeMemory (HGadget (cblake, csalt, ccounter)) (blake,salt) = do
    cellPoke cblake blake
    cellPoke csalt salt
    cellPoke ccounter 0

instance FinalizableMemory HGadgetBlake256 where
  type FV HGadgetBlake256 = (BLAKE256, Salt)

  finalizeMemory (HGadget (cblake, csalt, _)) = do
    blake <- cellPeek cblake
    salt <- cellPeek csalt
    return (blake, salt)

instance Gadget HGadgetBlake256 where
  type PrimitiveOf HGadgetBlake256 = BLAKE256

  apply (HGadget (cellBlake, cellSalt, cellCounter)) n cptr = do
    initial <- cellPeek cellBlake
    salt <- cellPeek cellSalt
    counter <- cellPeek cellCounter
    (final, nCounter , _ )  <- foldM (moveAndHash salt) (initial, counter, cptr) [1..n]
    cellPoke cellBlake final
    cellPoke cellCounter nCounter
    where
      sz = blockSize (undefined :: BLAKE256)
      moveAndHash salt (cxt, counter, ptr) _ = do
        let nCounter = counter + inBits sz
        newCxt       <- blake256CompressSingle cxt salt nCounter ptr
        return (newCxt, nCounter, ptr `movePtr` sz)


instance PaddableGadget (HGadgetBlake256) where
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
