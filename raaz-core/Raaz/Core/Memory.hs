{-|

Abstraction of a memory object.

-}

{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE GADTs                      #-}

module Raaz.Core.Memory
       ( Memory(..)
       , InitializableMemory(..)
       , FinalizableMemory(..)
       , withMemory, withSecureMemory , copyMemory
         -- * Memory cells
       , MemoryCell
       , cellPeek
       , cellPoke
       , cellModify
       , withCell
         -- Buffer
       , Bufferable(..)
       , MemoryBuf
       , withMemoryBuf
       ) where

import           Control.Applicative ( WrappedArrow(..) , (<$>) , (<*>))
import           Data.Monoid (Sum (..))
import           Foreign.Storable(Storable(..))
import           Foreign.Ptr (castPtr)

-- import           Raaz.Core.Memory.Internal
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr

------------------------ A memory allocator -----------------------

type ALIGNMonoid = Sum ALIGN

type AllocField = Field CryptoPtr

-- | A memory allocator. The allocator allocates memory from a fixed
-- chunk of memory pointed by a cryptoPtr.
type Alloc = TwistRF AllocField ALIGNMonoid

-- | Make an allocator for a given memory type.
makeAlloc :: LengthUnit l => l -> (CryptoPtr -> mem) -> Alloc mem
makeAlloc l memCreate = TwistRF (WrapArrow memCreate, Sum $ atLeast l)

-- | Any cryptographic primitives use memory to store stuff. This
-- class abstracts all types that hold some memory. Cryptographic
-- application often requires securing the memory from being swapped
-- out (think of memory used to store private keys or passwords). This
-- abstraction supports memory securing. If your platform supports
-- memory locking, then securing a memory will prevent the memory from
-- being swapped to the disk. Once secured the memory location is
-- overwritten by nonsense before being freed.
class Memory m where

  -- | Returns an allocator for this memory.
  memoryAlloc    :: Alloc m

  -- | Returns the pointer to the underlying buffer.
  underlyingPtr :: m -> CryptoPtr

  {-
  -- | This value @unsafeAllocate cptr@ creates a new instance of the
  -- memory @m@ with the underlying buffer being the memory pointed by
  -- @cptr@. The function in unsafe as it does not (and cannot) verify
  -- whether the passed pointer points to a valid memory location,
  -- i.e. has at least @allocSize m@ space, or whether it satisfies
  -- the allignment constraint.
  --
  -- It is highly unlikely that a user would need to use this function
  -- directly. Rather it is used to implement `withMemory` and
  -- `withSecureMemory`, the two combinators that any law abiding
  -- Haskell programmer should use when dealing with murky things like
  -- memory.
  unsafeAllocateMemory :: CryptoPtr -> m
  -}

-- | Copy data from a given memory location to the other. The first
-- argument is destionation and the second argument is source to match
-- with the convention followed in memcpy.
copyMemory :: Memory m => m -- ^ Destination
                       -> m -- ^ Source
                       -> IO ()
copyMemory dest src = memcpy (underlyingPtr dest) (underlyingPtr src) sz
  where sz = getSum $ twistMonoidValue $ getAlloc src
        getAlloc :: Memory m => m -> Alloc m
        getAlloc _ = memoryAlloc

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

-------------------------- The With combinators. ----------------

-- | Perform an action which makes use of this memory. The memory
-- allocated will automatically be freed when the action finishes
-- either gracefully or with some exception. Besides being safer,
-- this method might be more efficient as the memory might be
-- allocated from the stack directly and will have very little GC
-- overhead.
withMemory   :: Memory m => (m -> IO a) -> IO a
withMemory   = withM memoryAlloc
  where withM :: Memory m => Alloc m -> (m -> IO a) -> IO a
        withM alctr action = allocaBuffer sz $ action . getM
          where sz     = getSum $ twistMonoidValue alctr
                getM   = computeField $ twistFunctorValue alctr


-- | Similar to `withMemory` but allocates a secure memory for the
-- action. Secure memories are never swapped on to disk and will be
-- wiped clean of sensitive data after use. However, be careful when
-- using this function in a child thread. Due to the daemonic nature
-- of Haskell threads, if the main thread exists before the child
-- thread is done with its job, sensitive data can leak. This is
-- essentially a limitation of the bracket which is used internally.
withSecureMemory :: Memory m => (m -> IO a) -> IO a
withSecureMemory = withSM memoryAlloc
  where withSM :: Memory m => Alloc m -> (m -> IO a) -> IO a
        withSM alctr action = allocaSecure sz $ action . getM
          where sz     = getSum $ twistMonoidValue alctr
                getM   = computeField $ twistFunctorValue alctr

instance ( Memory a, Memory b) => Memory (a,b) where
  memoryAlloc  = (,) <$> memoryAlloc <*> memoryAlloc
  underlyingPtr (a,_) = underlyingPtr a

instance ( InitializableMemory a
         , InitializableMemory b
         ) => InitializableMemory (a,b) where
  type IV (a,b) = (IV a, IV b)
  initializeMemory (a,b) (iva, ivb) = initializeMemory a iva
                                   >> initializeMemory b ivb

instance ( FinalizableMemory a
         , FinalizableMemory b
         ) => FinalizableMemory (a,b) where
  type FV (a,b) = (FV a, FV b)
  finalizeMemory (a,b) =  (,) <$> finalizeMemory a
                              <*> finalizeMemory b

instance ( Memory a, Memory b, Memory c) => Memory (a,b,c) where
  memoryAlloc  = (,,) <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  underlyingPtr (a,_,_) = underlyingPtr a

instance ( InitializableMemory a
         , InitializableMemory b
         , InitializableMemory c
         ) => InitializableMemory (a,b,c) where
  type IV (a,b,c) = (IV a, IV b, IV c)
  initializeMemory (a,b,c) (iva, ivb, ivc) = initializeMemory a iva
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


---------------------------------------------------------------------
{--

-- | memory that does not hold anything.
instance Memory () where
  memoryAlloc    = pure ()
  underlyingPtr  = nullPtr

instance InitializableMemory () where
  type IV () = ()
  initializeMemory _ () = return ()

instance FinalizableMemory () where
  type FV () = ()
  finalizeMemory _ = return ()


instance (Memory a, Memory b) => Memory (a,b) where

  memoryAlloc                = (,) <$> memoryAlloc <*> memoryAlloc
  copyMemory (sa,sb) (da,db) = copyMemory sa da >> copyMemory sb db


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

--}

-- | A memory location to store a value of type having `Storable`
-- instance.
newtype MemoryCell a = MemoryCell { unMemoryCell :: CryptoPtr }

-- | Read the value from the MemoryCell.
cellPeek :: Storable a => MemoryCell a -> IO a
cellPeek = peek . castPtr . unMemoryCell

-- | Write the value to the MemoryCell.
cellPoke :: Storable a => MemoryCell a -> a -> IO ()
cellPoke = poke . castPtr . unMemoryCell

-- | Apply the given function to the value in the cell.
cellModify :: Storable a => MemoryCell a -> (a -> a) -> IO ()
cellModify cp f = cellPeek cp >>= cellPoke cp . f

-- | Perform some pointer action on MemoryCell. Useful while working
-- with ffi functions.
withCell :: MemoryCell a -> (CryptoPtr -> IO b) -> IO b
withCell (MemoryCell cptr) fp = fp cptr

instance Storable a => Memory (MemoryCell a) where

  memoryAlloc = allocator undefined
    where allocator :: Storable b => b -> Alloc (MemoryCell b)
          allocator b = makeAlloc (byteSize b) MemoryCell

  underlyingPtr (MemoryCell cptr) = cptr

instance Storable a => InitializableMemory (MemoryCell a) where
  type IV (MemoryCell a) = a
  initializeMemory = cellPoke

instance Storable a => FinalizableMemory (MemoryCell a) where
  type FV (MemoryCell a) = a
  finalizeMemory = cellPeek


-- | Types which can be stored in a buffer.
class Bufferable b where

  maxSizeOf         ::               b -> BYTES Int
  default maxSizeOf :: Storable b => b -> BYTES Int
  maxSizeOf = fromIntegral . sizeOf

-- | A memory buffer whose size depends on the `Bufferable` instance
-- of @b@.
data MemoryBuf b = MemoryBuf {-# UNPACK #-} !CryptoPtr

{-
-- | Size of the buffer.
memoryBufSize :: MemoryBuf b -> BYTES Int
memoryBufSize (MemoryBuf sz _) = sz
{-# INLINE memoryBufSize #-}
-}

-- | Perform some pointer action on `MemoryBuf`.
withMemoryBuf :: Bufferable b => MemoryBuf b -> (BYTES Int -> CryptoPtr -> IO a) -> IO a
withMemoryBuf mbuf@(MemoryBuf cptr) action =  action (maxSizeOf $ getBufferable mbuf) cptr
  where getBufferable :: Bufferable b => MemoryBuf b -> b
        getBufferable _ = undefined
{-# INLINE withMemoryBuf #-}

-- | Memory instance of `MemoryBuf`
instance Bufferable b => Memory (MemoryBuf b) where

  memoryAlloc = allocator undefined
    where allocator :: Bufferable b => b -> Alloc (MemoryBuf b)
          allocator b = makeAlloc (maxSizeOf b) MemoryBuf

  underlyingPtr (MemoryBuf cptr) = cptr
