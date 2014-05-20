{-|

Abstraction of a memory object.

-}

{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeFamilies      #-}

module Raaz.Core.Memory
       ( Memory(..)
       , InitializableMemory(..)
       , FinalizableMemory(..)
         -- CryptoCell
       , CryptoCell
       , cellPeek
       , cellPoke
       , cellModify
       , withCell
         -- Buffer
       , Bufferable(..)
       , MemoryBuf
       , memoryBufSize
       , withMemoryBuf
       ) where


import           Control.Applicative
import           Control.Exception         (bracket)
import           Foreign.ForeignPtr.Safe   (finalizeForeignPtr,
                                            mallocForeignPtrBytes,
                                            withForeignPtr)
import           Foreign.Ptr
import           Foreign.Storable


import           Raaz.Core.Memory.Internal
import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr


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

-- | The memory which can be initialized from an initial value.
class Memory m => InitializableMemory m where

  -- | Initial value of the memory.
  type IV m :: *

  -- | Initialize memory with the give IV.
  initializeMemory :: m -> IV m -> IO ()

-- | The memory from which a final value can be extracted.
class Memory m => FinalizableMemory m where

  -- | Final value of the memory.
  type FV m :: *

  -- | Get the final value from the memory.
  finalizeMemory :: m -> IO (FV m)

instance Memory () where
  newMemory = return ()
  freeMemory _ = return ()
  copyMemory _ _ = return ()
  withMemory f = f ()
  withSecureMemory f _ = f ()

instance InitializableMemory () where
  type IV () = ()
  initializeMemory _ () = return ()

instance FinalizableMemory () where
  type FV () = ()
  finalizeMemory _ = return ()

instance (Memory a, Memory b) => Memory (a,b) where
  newMemory = (,) <$> newMemory <*> newMemory
  freeMemory (a,b) = freeMemory a >> freeMemory b
  copyMemory (sa,sb) (da,db) = copyMemory sa da >> copyMemory sb db
  withSecureMemory f bk = withSecureMemory sec bk
    where sec b = withSecureMemory (\a -> f (a,b)) bk

instance ( InitializableMemory a
         , InitializableMemory b
         ) => InitializableMemory (a,b) where
  type IV (a,b) = (IV a, IV b)
  initializeMemory (a,b) (iva, ivb) =  initializeMemory a iva
                                    >> initializeMemory b ivb

instance ( FinalizableMemory a
         , FinalizableMemory b
         ) => FinalizableMemory (a,b) where
  type FV (a,b) = (FV a, FV b)
  finalizeMemory (a,b) =  (,) <$> finalizeMemory a
                              <*> finalizeMemory b

instance (Memory a, Memory b, Memory c) => Memory (a,b,c) where
  newMemory = (,,) <$> newMemory <*> newMemory <*> newMemory
  freeMemory (a,b,c) = freeMemory a >> freeMemory b >> freeMemory c
  copyMemory (sa,sb,sc) (da,db,dc) = copyMemory sa da
                                  >> copyMemory sb db
                                  >> copyMemory sc dc
  withSecureMemory f bk = withSecureMemory sec bk
    where sec c = withSecureMemory sec2 bk
            where sec2 b = withSecureMemory (\a -> f (a,b,c)) bk

instance ( InitializableMemory a
         , InitializableMemory b
         , InitializableMemory c
         ) => InitializableMemory (a,b,c) where
  type IV (a,b,c) = (IV a, IV b, IV c)
  initializeMemory (a,b,c) (iva, ivb, ivc) =  initializeMemory a iva
                                           >> initializeMemory b ivb
                                           >> initializeMemory c ivc

instance ( FinalizableMemory a
         , FinalizableMemory b
         , FinalizableMemory c
         ) => FinalizableMemory (a,b,c) where
  type FV (a,b,c) = (FV a, FV b, FV c)
  finalizeMemory (a,b,c) =  (,,) <$> finalizeMemory a
                                 <*> finalizeMemory b
                                 <*> finalizeMemory c

instance (Memory a, Memory b, Memory c, Memory d) => Memory (a,b,c,d) where
  newMemory = (,,,) <$> newMemory
                    <*> newMemory
                    <*> newMemory
                    <*> newMemory
  freeMemory (a,b,c,d) =  freeMemory a
                       >> freeMemory b
                       >> freeMemory c
                       >> freeMemory d
  copyMemory (sa,sb,sc,sd) (da,db,dc,dd) =  copyMemory sa da
                                         >> copyMemory sb db
                                         >> copyMemory sc dc
                                         >> copyMemory sd dd
  withSecureMemory f bk = withSecureMemory sec bk
    where sec d = withSecureMemory sec2 bk
            where sec2 c = withSecureMemory sec3 bk
                    where sec3 b = withSecureMemory (\a -> f (a,b,c,d)) bk

instance ( InitializableMemory a
         , InitializableMemory b
         , InitializableMemory c
         , InitializableMemory d
         ) => InitializableMemory (a,b,c,d) where
  type IV (a,b,c,d) = (IV a, IV b, IV c, IV d)
  initializeMemory (a,b,c,d) (iva, ivb, ivc, ivd) =  initializeMemory a iva
                                                  >> initializeMemory b ivb
                                                  >> initializeMemory c ivc
                                                  >> initializeMemory d ivd

instance ( FinalizableMemory a
         , FinalizableMemory b
         , FinalizableMemory c
         , FinalizableMemory d
         ) => FinalizableMemory (a,b,c,d) where
  type FV (a,b,c,d) = (FV a, FV b, FV c, FV d)
  finalizeMemory (a,b,c,d) =  (,,,) <$> finalizeMemory a
                                    <*> finalizeMemory b
                                    <*> finalizeMemory c
                                    <*> finalizeMemory d

-- | A memory location to store a value of type having `Storable`
-- instance.
newtype CryptoCell a = CryptoCell ForeignCryptoPtr

-- | Read the value from the CryptoCell.
cellPeek :: Storable a => CryptoCell a -> IO a
cellPeek (CryptoCell p) = withForeignPtr p (peek . castPtr)

-- | Write the value to the CryptoCell.
cellPoke :: Storable a => CryptoCell a -> a -> IO ()
cellPoke (CryptoCell p) v = withForeignPtr p (flip poke v . castPtr)

-- | Apply the given function to the value in the cell.
cellModify :: Storable a => CryptoCell a -> (a -> a) -> IO ()
cellModify cp f = cellPeek cp >>= cellPoke cp . f

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

instance Storable a => InitializableMemory (CryptoCell a) where
  type IV (CryptoCell a) = a
  initializeMemory = cellStore

instance Storable a => FinalizableMemory (CryptoCell a) where
  type FV (CryptoCell a) = a
  finalizeMemory = cellLoad

-- | Types which can be stored in a buffer.
class Bufferable b where

  maxSizeOf         ::               b -> BYTES Int
  default maxSizeOf :: Storable b => b -> BYTES Int

  maxSizeOf = fromIntegral . sizeOf

-- | A memory buffer whose size depends on the `Bufferable` instance
-- of @b@.
data MemoryBuf b = MemoryBuf {-# UNPACK #-} !(BYTES Int)
                             {-# UNPACK #-} !ForeignCryptoPtr

-- | Size of the buffer.
memoryBufSize :: MemoryBuf b -> BYTES Int
memoryBufSize (MemoryBuf sz _) = sz
{-# INLINE memoryBufSize #-}

-- | Perform some pointer action on `MemoryBuf`.
withMemoryBuf :: MemoryBuf a -> (CryptoPtr -> IO b) -> IO b
withMemoryBuf (MemoryBuf _ fp) = withForeignPtr fp
{-# INLINE withMemoryBuf #-}

-- | Memory instance of `MemoryBuf`
instance Bufferable b => Memory (MemoryBuf b) where
  newMemory = mal undefined
    where mal :: Bufferable b => b -> IO (MemoryBuf b)
          mal b = fmap (MemoryBuf size)
                  $ mallocForeignPtrBytes (fromIntegral size)
            where
              size = maxSizeOf b
  freeMemory (MemoryBuf _ fptr) = finalizeForeignPtr fptr
  copyMemory (MemoryBuf sz sf) (MemoryBuf _ df) = withForeignPtr sf do1
    where do1 sptr = withForeignPtr df (do2 sptr)
          do2 sptr dptr = memcpy dptr sptr sz
  withSecureMemory f bk = with undefined f
    where
      with :: Bufferable a => a -> (MemoryBuf a -> IO b) -> IO b
      with a action = withSecureMem bytes (action . MemoryBuf bytes) bk
        where
          bytes :: BYTES Int
          bytes = maxSizeOf a
