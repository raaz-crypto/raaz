{-|

Abstraction of a memory object.

-}

{-# LANGUAGE DefaultSignatures #-}

module Raaz.Memory
       ( Memory(..)
         -- CryptoCell
       , CryptoCell
       , cellLoad
       , cellStore
       , cellModify
       , withCell
         -- Buffer
       , Bufferable(..)
       , Buffer
       , bufferSize
       , withBuffer
       ) where


import Control.Applicative
import Control.Exception        ( bracket )
import Foreign.ForeignPtr.Safe  ( finalizeForeignPtr
                                , mallocForeignPtrBytes
                                , withForeignPtr
                                )
import Foreign.Ptr
import Foreign.Storable


import Raaz.Types
import Raaz.Util.Ptr
import Raaz.Util.SecureMemory


-- | Any cryptographic primitives use memory to store stuff. This
-- class abstracts all types that hold some memory. Besides the usual
-- operations of allocation and freeing, cryptographic application
-- often requires securing the memory from being swapped out (think of
-- memory used to store private keys or passwords). This abstraction
-- supports memory securing. If your platform supports memory locking,
-- then securing a memory will prevent the memory from being swapped
-- to the disk. Once secured the memory location is overwritten by
-- nonsense before being freed.
--
class Memory m where

  -- | Allocate the memory.
  newMemory    :: IO m

  -- | Free the memory.
  freeMemory   :: m -> IO ()

  -- | Copy Memory from Source to Destination
  copyMemory :: m -- ^ Source
             -> m -- ^ Destination
             -> IO ()

  -- | Perform an action which makes use of this memory. The memory
  -- allocated will automatically be freed when the action finishes
  -- either gracefully or with some exception. Besides being safer,
  -- this method might be more efficient as the memory might be
  -- allocated from the stack directly and will have very little GC
  -- overhead.
  withMemory   :: (m -> IO a) -> IO a
  withMemory = bracket newMemory freeMemory

  -- | Similar to `withMemory` but allocates a secure memory for the
  -- action.
  withSecureMemory :: (m -> IO a) -> PoolRef -> IO a

instance Memory () where
  newMemory = return ()
  freeMemory _ = return ()
  copyMemory _ _ = return ()
  withMemory f = f ()
  withSecureMemory f _ = f ()

instance (Memory a, Memory b) => Memory (a,b) where
  newMemory = (,) <$> newMemory <*> newMemory
  freeMemory (a,b) = freeMemory a >> freeMemory b
  copyMemory (sa,sb) (da,db) = copyMemory sa da >> copyMemory sb db
  withSecureMemory f bk = withSecureMemory sec bk
    where sec b = withSecureMemory (\a -> f (a,b)) bk

instance (Memory a, Memory b, Memory c) => Memory (a,b,c) where
  newMemory = (,,) <$> newMemory <*> newMemory <*> newMemory
  freeMemory (a,b,c) = freeMemory a >> freeMemory b >> freeMemory c
  copyMemory (sa,sb,sc) (da,db,dc) = copyMemory sa da
                                  >> copyMemory sb db
                                  >> copyMemory sc dc
  withSecureMemory f bk = withSecureMemory sec bk
    where sec c = withSecureMemory sec2 bk
            where sec2 b = withSecureMemory (\a -> f (a,b,c)) bk

-- | A memory location to store a value of type having `Storable`
-- instance.
newtype CryptoCell a = CryptoCell ForeignCryptoPtr

-- | Read the value from the CryptoCell.
cellLoad :: Storable a => CryptoCell a -> IO a
cellLoad (CryptoCell p) = withForeignPtr p (peek . castPtr)

-- | Write the value to the CryptoCell.
cellStore :: Storable a => CryptoCell a -> a -> IO ()
cellStore (CryptoCell p) v = withForeignPtr p (flip poke v . castPtr)

-- | Apply the given function to the value in the cell.
cellModify :: Storable a => CryptoCell a -> (a -> a) -> IO ()
cellModify cp f = cellLoad cp >>= cellStore cp . f

-- | Perform some pointer action on CryptoCell. Useful while working
-- with ffi functions.
withCell :: CryptoCell a -> (CryptoPtr -> IO b) -> IO b
withCell (CryptoCell fp) = withForeignPtr fp

instance Storable a => Memory (CryptoCell a) where
  newMemory = mal undefined
    where mal :: Storable a => a -> IO (CryptoCell a)
          mal = fmap CryptoCell . mallocForeignPtrBytes . sizeOf
  freeMemory (CryptoCell fptr) = finalizeForeignPtr fptr
  copyMemory scell dcell = withCell scell do1
    where do1 sptr = withCell dcell (do2 sptr)
          do2 sptr dptr = memcpy dptr sptr (BYTES $ sizeOf (getA scell))
          getA :: CryptoCell a -> a
          getA _ = undefined
  withSecureMemory f bk = with undefined f
    where
      with :: Storable a => a -> (CryptoCell a -> IO b) -> IO b
      with a action = withSecureMem bytes (action . CryptoCell) bk
        where
          bytes :: BYTES Int
          bytes = fromIntegral $ sizeOf a

-- | Types which can be stored in a buffer.
class Bufferable b where
  sizeOfBuffer :: b -> BYTES Int
  default sizeOfBuffer :: Storable b => b -> BYTES Int
  sizeOfBuffer = fromIntegral . sizeOf

-- | Buffer whose size depends on the `Bufferable` instance of @b@.
data Buffer b = Buffer {-# UNPACK #-} !(BYTES Int)
                       {-# UNPACK #-} !ForeignCryptoPtr

-- | Size of the buffer.
bufferSize :: Buffer b -> BYTES Int
bufferSize (Buffer sz _) = sz
{-# INLINE bufferSize #-}

-- | Perform some pointer action on Buffer.
withBuffer :: Buffer a -> (CryptoPtr -> IO b) -> IO b
withBuffer (Buffer _ fp) = withForeignPtr fp
{-# INLINE withBuffer #-}

-- | Memory instance of Buffer
instance Bufferable b => Memory (Buffer b) where
  newMemory = mal undefined
    where mal :: Bufferable b => b -> IO (Buffer b)
          mal b = fmap (Buffer size) $ mallocForeignPtrBytes (fromIntegral size)
            where
              size = sizeOfBuffer b
  freeMemory (Buffer _ fptr) = finalizeForeignPtr fptr
  copyMemory (Buffer sz sf) (Buffer _ df) = withForeignPtr sf do1
    where do1 sptr = withForeignPtr df (do2 sptr)
          do2 sptr dptr = memcpy dptr sptr (BYTES sz)
  withSecureMemory f bk = with undefined f
    where
      with :: Bufferable a => a -> (Buffer a -> IO b) -> IO b
      with a action = withSecureMem bytes (action . Buffer bytes) bk
        where
          bytes :: BYTES Int
          bytes = sizeOfBuffer a
