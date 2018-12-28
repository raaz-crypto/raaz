{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
-- | This module implements memory elements used for Poly1305
-- implementations.
module Raaz.Primitive.Poly1305.Memory
       ( Mem(..)
       , Element
       , elementToInteger
       ) where

import           Control.Monad.Reader
import           Data.Bits
import qualified Data.Vector.Unboxed as V
import           Data.Word
import           Raaz.Core.Types
import qualified Raaz.Core.Types.Internal        as TI
import           Raaz.Core.Memory
import           Raaz.Primitive.Poly1305.Internal


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

instance Memory Mem where
  memoryAlloc     = Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . accCell

instance Initialisable Mem (R,S) where
  initialise (r, s) = do withReaderT accCell $ initialise zeros
                         withReaderT rCell   $ initialise $ r
                         withReaderT sCell   $ initialise $ s
    where zeros :: Element
          zeros = unsafeFromList [0, 0, 0]

instance Extractable Mem Poly1305 where
    extract = toPoly1305 <$> withReaderT accCell extract
      where toPoly1305 = Poly1305 . TI.map littleEndian . project
            project :: Tuple 3 Word64 -> Tuple 2 Word64
            project = initial
