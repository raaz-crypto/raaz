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

import Control.Monad              ( when          )
import Control.Monad.Trans.Reader ( withReaderT   )
import Data.Word                  ( Word64        )
import Foreign.Storable           ( Storable(..)  )
import Foreign.Ptr                ( Ptr           )



import Raaz.Core hiding          ( alignment      )



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
getLength :: MT (HashMemory64 h) (BYTES Word64)
getLength =  withReaderT lengthCell extract

-- | Get the higher order 64-bits.
getULength :: MT (HashMemory128 h) (BYTES Word64)
getULength = withReaderT uLengthCell extract

-- | Get the lower order 64-bits
getLLength :: MT (HashMemory128 h)(BYTES Word64)
getLLength = withReaderT lLengthCell extract


-- | Get the pointer to the hash.
hashCellPointer :: Storable h
                => MT (HashMemory64 h)(Ptr h)
hashCellPointer = withReaderT hashCell getCellPointer
-- | Get the pointer to the array which stores the digest
hashCell128Pointer :: Storable h
                  => MT (HashMemory128 h) (Ptr h)
hashCell128Pointer = withReaderT hashCell128 getCellPointer



-- | Get the pointer to upper half of the length bytes.
lengthCellPointer :: Storable h
                   => MT (HashMemory64 h) (Ptr (BYTES Word64))
lengthCellPointer = withReaderT lengthCell getCellPointer

-- | Get the pointer to upper half of the length bytes.
uLengthCellPointer :: Storable h
                   => MT (HashMemory128 h) (Ptr (BYTES Word64))
uLengthCellPointer = withReaderT uLengthCell getCellPointer

-- | Get the pointer to the lower half of the length bytes.
lLengthCellPointer :: Storable h
                   => MT (HashMemory128 h) (Ptr (BYTES Word64))
lLengthCellPointer = withReaderT lLengthCell getCellPointer


-- | Update the length stored.
updateLength128 :: LengthUnit len
                => len
                -> MT (HashMemory128 h) ()
updateLength128 len =
  do l <- getLLength
     withReaderT lLengthCell $ initialise  (l + lenBytes)
     when (l > maxBound - lenBytes) $ withReaderT uLengthCell $ modify (+(1 :: BYTES Word64))
  where lenBytes = fromIntegral $ inBytes len

updateLength :: LengthUnit len
             => len
             -> MT (HashMemory64 h) ()
updateLength len = withReaderT lengthCell $ modify (+lenBytes)
  where lenBytes = fromIntegral $ inBytes len :: BYTES Word64

instance Storable h  => Memory (HashMemory128 h) where
  memoryAlloc     = HashMemory128 <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashCell128

instance Storable h  => Memory (HashMemory64 h) where
  memoryAlloc     = HashMemory64 <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashCell

instance Storable h => Initialisable (HashMemory128 h) h where
  initialise h = do withReaderT hashCell128 $ initialise h
                    withReaderT uLengthCell $ initialise (0 :: BYTES Word64)
                    withReaderT lLengthCell $ initialise (0 :: BYTES Word64)


instance Storable h => Initialisable (HashMemory64 h) h where
  initialise h = do withReaderT hashCell $ initialise h
                    withReaderT lengthCell $ initialise (0 :: BYTES Word64)


instance Storable h => Extractable (HashMemory128 h) h where
  extract = withReaderT hashCell128 extract

instance Storable h => Extractable (HashMemory64 h) h where
  extract = withReaderT hashCell extract
