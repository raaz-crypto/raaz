{-|

Abstraction of a memory object.

-}

module Raaz.Memory
       ( Memory(..)
         -- CryptoCell
       , CryptoCell(..)
       , cellLoad
       , cellStore
       , cellModify
       , withCell
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
  withSecureMemory :: (m -> IO a) -> BookKeeper -> IO a

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

  withSecureMemory f bk = allocSec undefined bk >>= f
   where wordAlign size | extra == 0 = size
                        | otherwise  = size + alignSize - extra
           where alignSize = sizeOf (undefined :: CryptoAlign)
                 extra = size `rem` alignSize

         allocSec :: Storable a => a -> BookKeeper -> IO (CryptoCell a)
         allocSec a = fmap CryptoCell .
                      allocSecureMem' (BYTES $ wordAlign $ sizeOf a)

-- -- | An array of values of type having `Storable` instance.
-- data CryptoArray a = CryptoArray ForeignCryptoPtr Int

-- -- | Read the value from `CryptoArray` at the given index. Index is
-- -- assumed to start from @0@.
-- loadFrom :: Storable a => CryptoArray a -> Int -> IO a
-- loadFrom arr@(CryptoArray _ s) n | s < n     = unsafeLoadFrom arr n
--                                  | otherwise = error "Illegal index"

-- -- | Write the value to `CryptoArray` at the given index.
-- storeAt :: Storable a => CryptoArray a -> Int -> a -> IO ()
-- storeAt arr@(CryptoArray _ s) n v | s < n     = unsafeStoreAt arr n v
--                                   | otherwise = error "Illegal index"

-- -- | This is unsafe version of `loadAt` as it does not check for overflow.
-- unsafeLoadFrom :: Storable a => CryptoArray a -> Int -> IO a
-- unsafeLoadFrom (CryptoArray p _) = withForeignPtr p . flip loadFromIndex

-- -- | This is unsafe version of `storeAt` as it does not check for overflow.
-- unsafeStoreAt :: Storable a => CryptoArray a -> Int -> a -> IO ()
-- unsafeStoreAt (CryptoArray p _) n = withForeignPtr p . (flip . flip storeAtIndex $ n)
