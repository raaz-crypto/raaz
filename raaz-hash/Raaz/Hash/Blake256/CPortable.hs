{-|

Portable C implementation of blake256 hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
--{-# LANGUAGE DoAndIfThenElse          #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/hash/blake256/portable.c  #-}

module Raaz.Hash.Blake256.CPortable () where

import Data.Word
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Blake256.Type

foreign import ccall unsafe
  "raaz/hash/blake256/portable.h raazHashBlake256PortableCompress"
  c_blake256_compress  :: CryptoPtr -> CryptoPtr -> BITS Word64 -> Int -> CryptoPtr -> IO ()

blake256Compress :: CryptoCell BLAKE256
                 -> CryptoCell Salt
                 -> BITS Word64
                 -> BLOCKS BLAKE256
                 -> CryptoPtr
                 -> IO ()
{-# INLINE blake256Compress #-}
blake256Compress cellBlake cellSalt counter nblocks buffer = withCell cellBlake action1
  where
    n = fromEnum nblocks
    action1 ptr = withCell cellSalt action2
      where
        action2 saltptr = c_blake256_compress ptr saltptr counter n buffer


instance Gadget (CGadget BLAKE256) where
  type PrimitiveOf (CGadget BLAKE256) = BLAKE256
  type MemoryOf (CGadget BLAKE256) = (CryptoCell BLAKE256, CryptoCell Salt, CryptoCell (BITS Word64))
  newGadgetWithMemory = return . CGadget

  initialize (CGadget (cellBlake, cellSalt, cellCounter)) (BLAKE256Cxt blake salt counter) = do
    cellStore cellSalt salt
    cellStore cellBlake blake
    cellStore cellCounter counter

  finalize (CGadget (cellBlake, cellSalt, cellCounter)) = do
    b <- cellLoad cellBlake
    s <- cellLoad cellSalt
    c <- cellLoad cellCounter
    return $ BLAKE256Cxt b s c

  apply (CGadget (cellBlake, cellSalt, cellCounter)) n cptr = do
    counter <- cellLoad cellCounter
    cellModify cellCounter $ (+) (inBits n)
    blake256Compress cellBlake cellSalt counter n cptr

instance PaddableGadget (CGadget BLAKE256) where
  unsafeApplyLast g@(CGadget (_, _, cellCounter)) blocks bytes cptr = do
    let bits      = inBits bytes
        len       = inBits blocks + bits
        p         = primitiveOf g
        block     = blockSize p
        padl      = padLength p len
        padBlocks = atMost padl `asTypeOf` blocks
        tBlocks   = atLeast (bytes + padl)
    unsafePad p len (cptr `movePtr` bytes)
    if padBlocks == 0
      then do
        apply g (tBlocks-1) cptr
        cellModify cellCounter (\a -> a - inBits padl)
        apply g 1 (cptr `movePtr` (tBlocks - 1))

      else do
        apply g (tBlocks-2) cptr
        cellModify cellCounter (\a -> a - inBits (padl - block))
        apply g 1 (cptr `movePtr` (tBlocks-2))
        cellStore cellCounter 0
        apply g 1 (cptr `movePtr` (tBlocks-1))
