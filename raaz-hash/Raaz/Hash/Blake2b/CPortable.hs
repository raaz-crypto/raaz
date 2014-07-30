{-|

Portable C implementation of blake2b hash.

-}

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE FlexibleInstances        #-}
--{-# LANGUAGE DoAndIfThenElse          #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/hash/blake2b/portable.c  #-}

module Raaz.Hash.Blake2b.CPortable () where

import Control.Applicative ( (<$>) )
import Data.Word
import Foreign.Ptr
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.Ptr
import Data.Bits
import Raaz.Hash.Blake2b.Type

foreign import ccall unsafe
  "raaz/hash/blake2b/portable.h raazHashBlake2bPortableCompress"
  c_blake2b_compress  :: CryptoPtr -> BITS Word64 -> Int -> CryptoPtr -> IO ()

blake2bCompress  :: CryptoCell BLAKE2B                               
                 -> BITS Word64
                 -> BLOCKS BLAKE2B
                 -> CryptoPtr 
                 -> IO ()
{-# INLINE blake2bCompress #-}
blake2bCompress cellBlake counter nblocks buffer = withCell cellBlake action1
  where 
    n = fromEnum nblocks    
    action1 ptr = c_blake2b_compress ptr counter n buffer      
      

instance Gadget (CGadget BLAKE2B) where
  type PrimitiveOf (CGadget BLAKE2B) = BLAKE2B
  type MemoryOf (CGadget BLAKE2B)    = (CryptoCell BLAKE2B, CryptoCell Salt, CryptoCell (BITS Word64))
  newGadgetWithMemory = return . CGadget
 
  initialize (CGadget (cellBlake, cellSalt, cellCounter)) (BLAKE2BCxt blake@(BLAKE2B h0 h1 h2 h3 h4 h5 h6 h7) salt counter) = do
    let a0 = h0 `xor` 0x0000000001010040
        a1 = h1 `xor` 0x0000000000000000
        a2 = h2 `xor` 0x0000000000000000
        a3 = h3 `xor` 0x0000000000000000
        a4 = h4 `xor` 0x0000000000000000
        a5 = h5 `xor` 0x0000000000000000
        a6 = h6 `xor` 0x0000000000000000
        a7 = h7 `xor` 0x0000000000000000

    cellStore cellSalt salt
    cellStore cellBlake (BLAKE2B a0 a1 a2 a3 a4 a5 a6 a7)   
    cellStore cellCounter counter
  
  finalize (CGadget (cellBlake, cellSalt, cellCounter)) = do
    b <- cellLoad cellBlake
    s <- cellLoad cellSalt
    c <- cellLoad cellCounter
    return $ BLAKE2BCxt b s c
  
  apply (CGadget cc@(cellBlake, cellSalt, cellCounter)) n cptr = do
    counter <- cellLoad cellCounter
    cellModify cellCounter (\a -> a + fromIntegral (roundFloor n :: BYTES Word64))      
    blake2bCompress cellBlake counter n cptr

instance PaddableGadget (CGadget BLAKE2B) where
  unsafeApplyLast g@(CGadget (_, _, counter)) blocks bytes cptr = do
    let bits  = roundFloor bytes :: BITS Word64
        len   = roundFloor blocks + bits
        p     = primitiveOf g
        padl  = padLength p len                        
        tBlocks = roundFloor (bytes + padl)
    unsafePad p len (cptr `movePtr` bytes)
    apply g (tBlocks-1) cptr
    cellModify counter (\a -> a - fromIntegral padl)
    apply g 1 (cptr `movePtr` (tBlocks-1))
        