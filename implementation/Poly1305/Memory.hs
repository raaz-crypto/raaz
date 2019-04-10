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

import           Control.Monad.Reader
import qualified Data.Vector.Unboxed as V
import           Foreign.Ptr                        ( Ptr, castPtr )
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
clearAcc :: MT Mem ()
clearAcc = withReaderT accCell $ initialise zero
  where zero :: Element
        zero = unsafeFromList [0,0,0]

instance Memory Mem where
  memoryAlloc     = Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . accCell


-- | Get the pointer to the array holding the key fragment r.
rKeyPtr  :: MT Mem  (Ptr (Tuple 2 Word64))
rKeyPtr  = castPtr  <$> withReaderT rCell getCellPointer

-- | Get the pointer to the array holding the key fragment s.
sKeyPtr  :: MT Mem (Ptr (Tuple 2 Word64))
sKeyPtr  = castPtr <$> withReaderT sCell getCellPointer

-- | Get the pointer to the accumulator array.
accumPtr :: MT Mem (Ptr Element)
accumPtr = withReaderT accCell getCellPointer

-- | The clamping operation
clamp :: MT Mem ()
clamp = rKeyPtr >>= liftIO . flip verse_poly1305_c_portable_clamp 1

instance Initialisable Mem (R,S) where
  initialise (r, s) = do clearAcc
                         withReaderT rCell   $ initialise $ r
                         withReaderT sCell   $ initialise $ s
                         clamp

instance Extractable Mem Poly1305 where
    extract = toPoly1305 <$> withReaderT accCell extract
      where toPoly1305 = Poly1305 . TI.map littleEndian . project
            project :: Tuple 3 Word64 -> Tuple 2 Word64
            project = initial

instance InitialisableFromBuffer Mem where
  initialiser mem = interleave clearAcc
                    `mappend` liftInit rCell mem
                    `mappend` liftInit sCell mem
                    `mappend` interleave clamp

    where liftRead f = liftTransfer (withReaderT f)
          liftInit f = liftRead f . initialiser . f
