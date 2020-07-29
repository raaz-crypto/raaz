{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Raaz.Primitive.HashMemory
       ( HashMemory128, HashMemory64
       , hashCellPointer, hashCell128Pointer
       , lengthCellPointer, uLengthCellPointer, lLengthCellPointer
       , getLength, getULength, getLLength
       , updateLength, updateLength128
       ) where


import Foreign.Storable           ( Storable(..)  )
import Foreign.Ptr                ( Ptr           )
import Raaz.Core



data HashMemory64 h = HashMemory64 { hashCell    :: MemoryCell h
                                   , lengthCell  :: MemoryCell (BYTES Word64)
                                   }

-- | Memory element that keeps track of a hash and the total bytes
-- processed (as a 128 bit quantity). Such a memory element is useful
-- for building the memory element for cryptographic hashes.

data HashMemory128 h = HashMemory128 { hashCell128 :: MemoryCell h
                                     , uLengthCell :: MemoryCell (BYTES Word64)
                                     , lLengthCell :: MemoryCell (BYTES Word64)
                                     }



-- | Get the length.
getLength :: HashMemory64 h -> IO (BYTES Word64)
getLength = extract . lengthCell

-- | Get the higher order 64-bits.
getULength :: HashMemory128 h -> IO (BYTES Word64)
getULength = extract . uLengthCell

-- | Get the lower order 64-bits
getLLength :: HashMemory128 h -> IO (BYTES Word64)
getLLength =  extract . lLengthCell


-- | Get the pointer to the hash.
hashCellPointer :: Storable h
                => HashMemory64 h
                -> Ptr h
hashCellPointer = getCellPointer . hashCell
-- | Get the pointer to the array which stores the digest
hashCell128Pointer :: Storable h
                  => HashMemory128 h
                  -> Ptr h
hashCell128Pointer = getCellPointer . hashCell128



-- | Get the pointer to upper half of the length bytes.
lengthCellPointer :: Storable h
                   => HashMemory64 h
                   -> Ptr (BYTES Word64)
lengthCellPointer = getCellPointer . lengthCell

-- | Get the pointer to upper half of the length bytes.
uLengthCellPointer :: Storable h
                   => HashMemory128 h
                   -> Ptr (BYTES Word64)
uLengthCellPointer = getCellPointer . uLengthCell

-- | Get the pointer to the lower half of the length bytes.
lLengthCellPointer :: Storable h
                   => HashMemory128 h
                   -> Ptr (BYTES Word64)
lLengthCellPointer = getCellPointer . lLengthCell


-- | Update the length stored.
updateLength128 :: LengthUnit len
                => len
                -> HashMemory128 h
                -> IO ()
updateLength128 len hmem =
  do l <- getLLength hmem
     initialise (l + lenBytes) $ lLengthCell hmem
     when (l > maxBound - lenBytes) $
       modifyMem (+(1 :: BYTES Word64)) $ uLengthCell hmem
  where lenBytes = fromIntegral $ inBytes len

updateLength :: LengthUnit len
             => len
             -> HashMemory64 h
             -> IO ()
updateLength len = modifyMem (+lenBytes) . lengthCell
  where lenBytes = fromIntegral $ inBytes len :: BYTES Word64

instance Storable h  => Memory (HashMemory128 h) where
  memoryAlloc     = HashMemory128 <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashCell128

instance Storable h  => Memory (HashMemory64 h) where
  memoryAlloc     = HashMemory64 <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashCell

instance Storable h => Initialisable (HashMemory128 h) h where
  initialise h hmem = do initialise h $ hashCell128 hmem
                         initialise (0 :: BYTES Word64) $ uLengthCell hmem
                         initialise (0 :: BYTES Word64) $ lLengthCell hmem


instance Storable h => Initialisable (HashMemory64 h) h where
  initialise h hmem = do initialise h $ hashCell hmem
                         initialise (0 :: BYTES Word64) $ lengthCell hmem


instance Storable h => Extractable (HashMemory128 h) h where
  extract = extract . hashCell128

instance Storable h => Extractable (HashMemory64 h) h where
  extract = extract . hashCell
