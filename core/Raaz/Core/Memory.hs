{-|

The memory subsystem associated with raaz.


__Warning:__ This module is pretty low level and should not be needed in typical
use cases. Only developers of protocols and primitives might have a
reason to look into this module.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE DataKinds                  #-}
module Raaz.Core.Memory
       (
       -- * The Memory subsystem.
       -- $memorysubsystem$

       -- ** Memory elements.
         Memory(..), VoidMemory, copyMemory
       -- *** Initialisation and Extraction.
       -- $init-extract$
       , Initialisable(..), Extractable(..)
       , InitialisableFromBuffer(..), ExtractableToBuffer(..)
       -- *** A basic memory cell.
       , MemoryCell, withCellPointer, getCellPointer

       -- ** MemoryMonad .
       , MonadMemoryT (..), modify
       , MT
       -- ** Memory allocation
       ,  Alloc, pointerAlloc
       ) where

import           Control.Applicative
import           Control.Monad.Reader
import           Foreign.Storable            ( Storable )
import           Foreign.Ptr                 ( castPtr, Ptr )
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Transfer
import           Raaz.Core.Types
import           Raaz.Core.IOCont

-- $memorysubsystem$
--
-- Cryptographic operations often need to keep sensitive information
-- like private keys in its memory space. Such sensitive information
-- can leak to the external would if the memory where the data is
-- stored is swapped out to a disk. What makes this particularly
-- dangerous is that the data can reside on the disk almost
-- permanently and might even survive when the hardware is
-- scrapped. The primary purpose of the memory subsystem is to provide
-- a way to allocate and manage /secure memory/, i.e. memory that will
-- not be swapped out as long as the memory is used and will be wiped
-- clean after use. It consists of the following components:
--
-- [The `Memory` type class:] A memory element is some type that holds
-- an internal buffer inside it.
--
-- [The `Alloc` type:] Memory elements need to be allocated and this
-- is involves a lot of low lever pointer arithmetic. The `Alloc`
-- types gives a high level interface for memory allocation. For a
-- memory type `mem`, the type `Alloc mem` can be seen as the
-- _allocation strategy_ for mem. For example, one of the things that
-- it keeps track of is the space required to create an memory element
-- of type `mem`. There is a natural applicative instance for `Alloc`
-- which helps build the allocation strategy for a compound memory
-- type from its components in a modular fashion _without_ explicit
-- size calculation or offset computation.
--
-- [`MemoryThread`s:] Instances of this class are actions that use
-- some kind of memory elements inside it. Such a thread can be run
-- using the combinator `securely` or the combinator `insecurely`. If
-- one use the combinator `securely`, then the allocation of the
-- memory element to be used by the action is done using a locked
-- memory pool which is wiped clean before de-allocation.

-- $init-extract$
--
-- Memory elements often needs to be initialised. Similarly data needs
-- to be extracted out of memory. An instance declaration
-- @`Initialisable` mem a@ for the memory type @mem@ indicates that it
-- can be initialised with the pure value @a@. Similary, if values of
-- type @b@ can be extracted out of a memory element @mem@, we can
-- indicate it with an instance of @`Extractable` mem a@.
--
-- There is an inherent danger in initialising and extracting pure
-- values out of memory. Pure values are stored on the Haskell heap
-- and hence can be swapped out. Consider a memory element @mem@ that
-- stores some sensitive information, say for example the unencrypted
-- private key. Suppose we extract this key out of the memory element
-- as a pure value before its encryption and storage into the key
-- file. It is likely that the key is swapped out to the disk as the
-- extracted key is part of the the haskell heap.
--
-- The `InitialiseFromBuffer` (`ExtractableToBuffer`) class gives an
-- interface for reading from (writing to) buffers directly minimising
-- the chances of inadvertent exposure of sensitive information from
-- the Haskell heap due to swapping.


-- | An action of type @`MT` mem a@ is an action that uses internally
-- a single memory object of type @mem@ and returns a result of type
-- @a@. All the actions are performed on a single memory element and
-- hence the side effects persist. It is analogues to the @ST@ monad.
type MT mem = ReaderT mem IO

-- | A class that captures abstract "memory threads". A memory thread
-- can either be run `securely` or `insecurely`. Pure IO actions can
-- be run inside a memory thread using the @runIO@.  However, the IO
-- action that is being run /must not/ directly or indirectly run a
-- `secure` action ever. In particular, the following code is bad.
--
-- > -- BAD EXAMPLE: DO NOT USE.
-- > runIO $ securely $ foo
-- >
--
-- On the other hand the following code is fine
--
-- >
-- > runIO $ insecurely $ someMemoryAction
-- >
--
-- As to why this is dangerous, it has got to do with the fact that
-- @mlock@ and @munlock@ do not nest correctly. A single @munlock@ can
-- unlock multiple calls of @mlock@ on the same page.  Whether a given
-- @IO@ action unlocks memory is difficult to keep track of; for all
-- you know, it might be a FFI call that does an @memunlock@. Hence,
-- currently there is no easy way to enforce this.
--

class MonadMemoryT mT where
  -- | Run a memory action with the internal memory allocated from a
  -- locked memory buffer. This memory buffer will never be swapped
  -- out by the operating system and will be wiped clean before
  -- releasing.
  --
  -- Memory locking is an expensive operation and usually there would be
  -- a limit to how much locked memory can be allocated. Nonetheless,
  -- actions that work with sensitive information like passwords should
  -- use this to run an memory action.
  securely   :: MonadIOCont m => mT m a -> m a

  -- | Run a memory action with the internal memory used by the action
  -- being allocated from unlocked memory. Use this function when you
  -- work with data that is not sensitive to security considerations
  -- (for example, when you want to verify checksums of files).
  insecurely :: MonadIOCont m => mT m a -> m a


instance Memory mem => MonadMemoryT (ReaderT mem) where
  securely               = withSecureMemory . runReaderT
  insecurely             = withMemory . runReaderT

{--
  liftMT                 = id
  onSubMemory proj mtsub = MT $ withReaderunMT mtsub . proj
--}

{--
------------- Lifting pointer actions -----------------------------


-- | Run a given memory action in the memory thread.
execute :: MemoryThread mT => (mem -> IO a) -> mT mem a
execute = liftMT . MT

-- | Perform an IO action inside the memory thread.
doIO :: MemoryThread mT => IO a -> mT mem a
doIO = execute . const

-- TODO: This is a very general pattern needs more exploration.

-- | Get the underlying memory element of the memory thread.
getMemory :: MemoryThread mT => mT mem mem
getMemory = execute return

--}

------------------------ A memory allocator -----------------------


type AllocField = Field Pointer

-- | A memory allocator for the memory type @mem@. The `Applicative`
-- instance of @Alloc@ can be used to build allocations for
-- complicated memory elements from simpler ones.
type Alloc mem = TwistRF AllocField (BYTES Int) mem

-- | Make an allocator for a given memory type.
makeAlloc :: LengthUnit l => l -> (Pointer -> mem) -> Alloc mem
makeAlloc l memCreate = TwistRF (WrapArrow memCreate) $ atLeast l

-- | Allocates a buffer of size @l@ and returns the pointer to it pointer.
pointerAlloc :: LengthUnit l => l -> Alloc Pointer
pointerAlloc l = makeAlloc l id

---------------------------------------------------------------------

-- | Any cryptographic primitives use memory to store stuff. This
-- class abstracts all types that hold some memory. Cryptographic
-- application often requires securing the memory from being swapped
-- out (think of memory used to store private keys or passwords). This
-- abstraction supports memory securing. If your platform supports
-- memory locking, then securing a memory will prevent the memory from
-- being swapped to the disk. Once secured the memory location is
-- overwritten by nonsense before being freed.
--
-- While some basic memory elements like `MemoryCell` are exposed from
-- the library, often we require compound memory objects built out of
-- simpler ones. The `Applicative` instance of the `Alloc` can be made
-- use of in such situation to simplify such instance declaration as
-- illustrated in the instance declaration for a pair of memory
-- elements.
--
-- > instance (Memory ma, Memory mb) => Memory (ma, mb) where
-- >
-- >    memoryAlloc             = (,) <$> memoryAlloc <*> memoryAlloc
-- >
-- >    unsafeToPointer (ma, _) =  unsafeToPointer ma
--
class Memory m where

  -- | Returns an allocator for this memory.
  memoryAlloc     :: Alloc m

  -- | Returns the pointer to the underlying buffer.
  unsafeToPointer :: m -> Pointer


-- | A memory element that holds nothing.
newtype VoidMemory = VoidMemory { unVoidMemory :: Pointer  }

--
-- DEVELOPER NOTE:
--
-- It might be tempting to define VoidMemory as follows.
--
-- >
-- > newtype VoidMemory = VoidMemory
-- >
--
-- However, this will lead to failure of memory instances of product
-- memories where the first component is VoidMemory. Imagine what
-- would the member function unsafeToPointer of (VoidMemory,
-- SomeOtherMemory) look like.
--
instance Memory VoidMemory where
  memoryAlloc      = makeAlloc (0 :: BYTES Int) VoidMemory
  unsafeToPointer  = unVoidMemory


instance ( Memory ma, Memory mb ) => Memory (ma, mb) where
    memoryAlloc             = (,) <$> memoryAlloc <*> memoryAlloc
    unsafeToPointer (ma, _) = unsafeToPointer ma

instance ( Memory ma
         , Memory mb
         , Memory mc
         )
         => Memory (ma, mb, mc) where
  memoryAlloc              = (,,)
                             <$> memoryAlloc
                             <*> memoryAlloc
                             <*> memoryAlloc
  unsafeToPointer (ma,_,_) =  unsafeToPointer ma

instance ( Memory ma
         , Memory mb
         , Memory mc
         , Memory md
         )
         => Memory (ma, mb, mc, md) where
  memoryAlloc                = (,,,)
                               <$> memoryAlloc
                               <*> memoryAlloc
                               <*> memoryAlloc
                               <*> memoryAlloc

  unsafeToPointer (ma,_,_,_) =  unsafeToPointer ma

-- | Copy data from a given memory location to the other. The first
-- argument is destionation and the second argument is source to match
-- with the convention followed in memcpy.
copyMemory :: Memory m => Dest m -- ^ Destination
                       -> Src  m -- ^ Source
                       -> IO ()
copyMemory dmem smem = memcpy (unsafeToPointer <$> dmem) (unsafeToPointer <$> smem) sz
  where sz       = twistMonoidValue $ getAlloc smem
        getAlloc :: Memory m => Src m -> Alloc m
        getAlloc _ = memoryAlloc

-- | Perform an action which makes use of this memory. The memory
-- allocated will automatically be freed when the action finishes
-- either gracefully or with some exception. Besides being safer,
-- this method might be more efficient as the memory might be
-- allocated from the stack directly and will have very little GC
-- overhead.
withMemory   :: MonadIOCont m => Memory mem => (mem -> m a) -> m a
withMemory   = withM memoryAlloc
  where withM :: MonadIOCont m => Alloc mem -> (mem -> m a) -> m a
        withM alctr action = allocaBuffer sz actualAction
          where sz                 = twistMonoidValue alctr
                getM               = computeField $ twistFunctorValue alctr
                wipeIt cptr        = wipe_memory cptr sz
                actualAction  cptr = action (getM cptr) <* wipeIt cptr


-- | Similar to `withMemory` but allocates a secure memory for the
-- action. Secure memories are never swapped on to disk and will be
-- wiped clean of sensitive data after use. However, be careful when
-- using this function in a child thread. Due to the daemonic nature
-- of Haskell threads, if the main thread exists before the child
-- thread is done with its job, sensitive data can leak. This is
-- essentially a limitation of the bracket which is used internally.
withSecureMemory :: (MonadIOCont m, Memory mem) => (mem -> m a) -> m a
withSecureMemory = withSM memoryAlloc
  where -- withSM :: Memory m => Alloc m -> (m -> IO a) -> IO a
        withSM alctr action = allocaSecure sz $ action . getM
          where sz     = twistMonoidValue alctr
                getM   = computeField $ twistFunctorValue alctr


----------------------- Initialising and Extracting stuff ----------------------

-- | Memories that can be initialised with a pure value. The pure
-- value resides in the Haskell heap and hence can potentially be
-- swapped. Therefore, this class should be avoided if compromising
-- the initialisation value can be dangerous. Consider using
-- `InitialiseableFromBuffer`
--

class Memory m => Initialisable m v where
  initialise :: v -> MT m ()

-- | Memories from which pure values can be extracted. Once a pure value is
-- extracted,
class Memory m => Extractable m v where
  extract  :: MT m v


-- | Apply the given function to the value in the cell. For a function @f :: b -> a@,
-- the action @modify f@ first extracts a value of type @b@ from the
-- memory element, applies @f@ to it and puts the result back into the
-- memory.
--
-- > modify f = do b          <- extract
-- >               initialise $  f b
--
modify :: (Initialisable mem a, Extractable mem b) =>  (b -> a) -> MT mem ()
modify f = extract >>= initialise . f

-- | A memory type that can be initialised from a pointer buffer. The initialisation performs
-- a direct copy from the input buffer and hence the chances of the
-- initialisation value ending up in the swap is minimised.
class Memory m => InitialisableFromBuffer m where
  initialiser :: m -> ReadM (MT m)

-- | A memory type that can extract bytes into a buffer. The extraction will perform
-- a direct copy and hence the chances of the extracted value ending
-- up in the swap space is minimised.
class Memory m => ExtractableToBuffer m where
  extractor :: m -> WriteM (MT m)

--------------------- Some instances of Memory --------------------

-- | A memory location to store a value of type having `Storable`
-- instance.
newtype MemoryCell a = MemoryCell { unMemoryCell :: Ptr a }


instance Storable a => Memory (MemoryCell a) where

  memoryAlloc = allocator undefined
    where allocator :: Storable b => b -> Alloc (MemoryCell b)
          allocator b = makeAlloc (alignedSizeOf $ pure b) $ MemoryCell . castPtr

  unsafeToPointer  = castPtr . unMemoryCell

-- | The location where the actual storing of element happens. This
-- pointer is guaranteed to be aligned to the alignment restriction of @a@
actualCellPtr :: Storable a => MemoryCell a -> Ptr a
actualCellPtr = nextLocation . unMemoryCell

-- | Work with the underlying pointer of the memory cell. Useful while
-- working with ffi functions.
withCellPointer :: Storable a => (Ptr a -> IO b) -> MT (MemoryCell a) b
{-# INLINE withCellPointer #-}
withCellPointer action = ReaderT $ action . actualCellPtr


-- | Get the pointer associated with the given memory cell.
getCellPointer :: Storable a => MT (MemoryCell a) (Ptr a)
{-# INLINE getCellPointer #-}
getCellPointer = actualCellPtr <$> ask

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = ReaderT $ flip pokeAligned a . unMemoryCell
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = ReaderT $ peekAligned . unMemoryCell
  {-# INLINE extract #-}

instance EndianStore a => InitialisableFromBuffer (MemoryCell a) where
  initialiser  = readInto 1 . destination . actualCellPtr

instance EndianStore a => ExtractableToBuffer (MemoryCell a) where
  extractor  = writeFrom 1 . source . actualCellPtr
