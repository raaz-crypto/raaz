{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
-- | This module implements memory elements used for Poly1305
-- implementations.
module Poly1305.Memory
       ( Mem(..)
       , Element
       , elementToInteger
       , rKeyPtr
       , sKeyPtr
       , accumPtr
       ) where

import qualified Data.Vector.Unboxed as V
import           Foreign.Ptr                        ( castPtr )
import           Raaz.Core
import qualified Raaz.Core.Types.Internal        as TI
import           Raaz.Primitive.Poly1305.Internal

import           Raaz.Verse.Poly1305.C.Portable (verse_poly1305_c_portable_clamp)

-- | An element in the finite field GF(2¹³⁰ - 5) requires 130 bits
-- which is stored as three 64-bit word where the last word has only
-- 2-bits.
type Element = Tuple 3 Word64


-- | Convert the element to an integer.
elementToInteger :: Element -> Integer
elementToInteger = V.foldr fld 0 . unsafeToVector
  where fld :: Word64 -> Integer -> Integer
        fld w i = toInteger w + i `shiftL` 32


-- | The memory associated with Poly1305 stores the
data Mem = Mem { accCell :: MemoryCell Element
               , rCell   :: MemoryCell R
               , sCell   :: MemoryCell S
               }

-- | Clearing the accumulator.
clearAcc :: Mem -> IO ()
clearAcc = initialise zero . accCell
  where zero :: Element
        zero = unsafeFromList [0,0,0]

instance Memory Mem where
  memoryAlloc     = Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . accCell


-- | Get the pointer to the array holding the key fragment r.
rKeyPtr  :: Mem  -> Ptr (Tuple 2 Word64)
rKeyPtr  = castPtr . unsafeGetCellPointer . rCell

-- | Get the pointer to the array holding the key fragment s.
sKeyPtr  :: Mem -> Ptr (Tuple 2 Word64)
sKeyPtr  = castPtr . unsafeGetCellPointer . sCell

-- | Get the pointer to the accumulator array.
accumPtr :: Mem -> Ptr Element
accumPtr = castPtr . unsafeGetCellPointer .  accCell

-- |  The clamping function on pointer
clampPtr :: Ptr (Tuple 2 Word64) -> IO ()
clampPtr = flip verse_poly1305_c_portable_clamp 1

-- | The clamping operation
clamp :: Mem -> IO ()
clamp =  clampPtr . rKeyPtr

instance Initialisable Mem (Key Poly1305) where
  initialise (Key r s) mem = do clearAcc mem
                                initialise r $ rCell mem
                                initialise s $ sCell mem
                                clamp mem

instance Extractable Mem Poly1305 where
    extract = fmap toPoly1305 . extract . accCell
      where toPoly1305 = Poly1305 . TI.map littleEndian . project
            project :: Tuple 3 Word64 -> Tuple 2 Word64
            project = initial

instance WriteAccessible Mem where
  writeAccess mem          = writeAccess (rCell mem) ++ writeAccess (sCell mem)
  afterWriteAdjustment mem = do
    clearAcc mem
    afterWriteAdjustment $ rCell mem
    afterWriteAdjustment $ sCell mem
    clamp mem
