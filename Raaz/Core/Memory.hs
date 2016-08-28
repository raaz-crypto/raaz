{-|

The memory subsystem associated with raaz.


__Warning:__ This module is pretty low level and should not be needed in typical
use cases. Only developers of protocols and primitives might have a
reason to look into this module.

-}

{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Core.Memory
       (
       -- * The Memory subsystem.
       -- $memorysubsystem$

       -- ** Initialisation and Extraction.
       -- $init-extract$
         Memory(..), copyMemory
       , Initialisable(..), Extractable(..)
       , InitialisableFromBuffer(..), ExtractableToBuffer(..)
       -- *** A basic memory cell.
       , MemoryCell

       -- *** Actions on memory elements.
       , MT,  execute, getMemory, liftSubMT, modify
       -- **** Some low level `MT` actions.
       , getMemoryPointer, withPointer
       , allocate
       -- ** Generic memory monads.
       , MonadMemory(..)
       , MemoryM, runMT
       -- ** Memory allocation
       ,  Alloc, pointerAlloc
       ) where

import           Control.Applicative
import           Control.Monad.IO.Class
import           Foreign.Storable            ( Storable(..) )
import           Foreign.Ptr                 ( castPtr, Ptr )
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Transfer
import           Raaz.Core.Types

-- $memorysubsystem$
--
-- Cryptographic operations often need to keep sensitive information
-- in its memory space. If this memory is swapped out to the disk,
-- this can be dangerous. The primary purpose of the memory subsystem
-- in raaz provides a way to allocate and manage _secure memory_,
-- i.e. memory that will not be swapped out during the execution of
-- the process and will be wiped clean after use. There are there
-- important parts to the memory subsystem:
--
-- [The `Memory` type class:] A memory element is some type that holds
-- an internal buffer inside it.
--
-- [The `Alloc` type:] Memory elements need to be allocated and this
-- is involves a lot of low lever pointer arithmetic. The `Alloc`
-- types gives a high level interface for memory allocation. For a
-- memory type `mem`, the type `Alloc mem` can be seen as the
-- _allocation strategy_ for mem. For example, one of the things that
-- it keeps track of the space required to create an memory element of
-- type `mem`. There is a natural applicative instance for `Alloc`
-- which helps build the allocation strategy for a compound memory
-- type from its components in a modular fashion _without_ explicit
-- size calculation or offset computation.
--
-- [The `MonadMemory` class:] Instances of these classes are actions
-- that use some kind of memory elements, i.e. instances of the class
-- `Memory`, inside it. Any such monad can either be run using the
-- combinator `securely` or the combinator `insecurely`. If one use
-- the combinator `securely`, then all allocations done during the run
-- is from a locked memory pool which is wiped clean before
-- de-allocation. The types `MT` and `MemoryM` are two instances that
-- we expose from this library.
--

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
-- values out of memory. Pure values are stored on the Haskell stack
-- and hence can be swapped out. Consider a memory element @mem@ that
-- stores some sensitive information, say for example the unencrypted
-- private key. Now suppose that we need to extracting out the key as
-- a pure value before its encryption and storage into the key file,
-- it is likely that the key is swapped out to the disk as part of the
-- haskell heap.
--
-- The `InitialiseFromBuffer` (`ExtractableToBuffer`) class gives an
-- interface for reading from (writing to) buffers directly minimising
-- the chances of inadvertent exposure of sensitive information from
-- the Haskell heap due to swapping.

-- | A class that captures monads that use an internal memory element.
--
-- Any instance of `MonadMemory` can be executed `securely` in which
-- case all allocations are performed from a locked pool of
-- memory. which at the end of the operation is also wiped clean
-- before deallocation.
--
-- Systems often put tight restriction on the amount of memory a
-- process can lock.  Therefore, secure memory is often to be used
-- judiciously. Instances of this class /should/ also implement the
-- the combinator `insecurely` which allocates all memory from an
-- unlocked memory pool.
--
-- This library exposes two instances of `MonadMemory`
--
-- 1. /Memory threads/ captured by the type `MT`, which are a sequence
-- of actions that use the same memory element and
--
-- 2. /Memory actions/ captured by the type `MemoryM`.
--
-- /WARNING:/ Be careful with `liftIO`.
--
-- The rule of thumb to follow is that the action being lifted should
-- itself never unlock any memory. In particular, the following code
-- is bad because the `securely` action unlocks some portion of the
-- memory after @foo@ is executed.
--
-- >
-- >  liftIO $ securely $ foo
-- >
--
-- On the other hand the following code is fine
--
-- >
-- > liftIO $ insecurely $ someMemoryAction
-- >
--
-- Whether an @IO@ action unlocks memory is difficult to keep track
-- of; for all you know, it might be a FFI call that does an
-- @memunlock@.
--
-- As to why this is dangerous, it has got to do with the fact that
-- @mlock@ and @munlock@ do not nest correctly. A single @munlock@ can
-- unlock multiple calls of @mlock@ on the same page.
--
class (Monad m, MonadIO m) => MonadMemory m where
  -- | Perform the memory action where all memory elements are allocated
  -- locked memory. All memory allocated will be locked and hence will
  -- never be swapped out by the operating system. It will also be wiped
  -- clean before releasing.
  --
  -- Memory locking is an expensive operation and usually there would be
  -- a limit to how much locked memory can be allocated. Nonetheless,
  -- actions that work with sensitive information like passwords should
  -- use this to run an memory action.
  securely   :: m a -> IO a


  -- | Perform the memory action where all memory elements are
  -- allocated unlocked memory. Use this function when you work with
  -- data that is not sensitive to security considerations (for example,
  -- when you want to verify checksums of files).
  insecurely :: m a -> IO a


-- | An action of type @`MT` mem a@ is an action that uses internally
-- a a single memory object of type @mem@ and returns a result of type
-- @a@. All the actions are performed on a single memory element and
-- hence the side effects persist. It is analogues to the @ST@
-- monad.
newtype MT mem a = MT { unMT :: mem -> IO a }

-- | Given an memory thread
allocate :: LengthUnit bufSize
         => bufSize -> (Pointer -> MT mem a) -> MT mem a
allocate bufSize bufAction
  = execute $ \ mem ->
  allocaBuffer bufSize (\ptr -> unMT (bufAction ptr) mem)

-- | Run a given memory action in the memory thread.
execute :: (mem -> IO a) -> MT mem a
{-# INLINE execute #-}
execute = MT

getMemory :: MT mem mem
getMemory = execute return

-- | Get the pointer associated with the given memory.
getMemoryPointer :: Memory mem => MT mem Pointer
getMemoryPointer = underlyingPtr <$> getMemory

-- | Work with the underlying pointer of the memory element. Useful
-- while working with ffi functions.
withPointer :: Memory mem => (Pointer -> IO b) -> MT mem b
withPointer fp  = execute $ fp . underlyingPtr
{-# INLINE withPointer #-}

-- | Compound memory elements might intern be composed of
-- sub-elements. Often one might want to /lift/ the memory thread for
-- a sub-element to the compound element. Given a sub-element of type
-- @mem'@ which can be obtained from the compound memory element of
-- type @mem@ using the projection @proj@, @liftSubMT proj@ lifts the
-- a memory thread of the sub element to the compound element.
--
liftSubMT :: (mem -> mem') -- ^ Projection from the compound element
                           -- to sub-element
          -> MT mem' a     -- ^ Memory thread of the sub-element.
          -> MT mem  a
liftSubMT proj mt' = execute $ unMT mt' . proj

instance Functor (MT mem) where
  fmap f mst = MT $ \ m -> f <$> unMT mst m

instance Applicative (MT mem) where
  pure       = MT . const . pure
  mf <*> ma  = MT $ \ m -> unMT mf m <*> unMT ma m

instance Monad (MT mem) where
  return    =  MT . const . return
  ma >>= f  =  MT runIt
    where runIt mem = unMT ma mem >>= \ a -> unMT (f a) mem

instance MonadIO (MT mem) where
  liftIO = MT . const

instance Memory mem => MonadMemory (MT mem) where

  securely   = withSecureMemory . unMT
  insecurely = withMemory       . unMT

-- | A runner of a memory state thread.
type    Runner mem b = MT mem b -> IO b

-- | A memory action that uses some sort of memory element
-- internally.
newtype MemoryM a = MemoryM
   { unMemoryM :: (forall mem b. Memory mem => Runner mem b) -> IO a }


instance Functor MemoryM where
  fmap f mem = MemoryM $ \ runner -> f <$> unMemoryM mem runner

instance Applicative MemoryM where
  pure  x       = MemoryM $ \ _ -> return x
  -- Beware: do not follow the hlint suggestion. The ugly definition
  -- is to avoid usage of impredicative polymorphism.

  memF <*> memA = MemoryM $ \ runner ->  unMemoryM memF runner <*> unMemoryM memA runner

instance Monad MemoryM where
  return = pure
  memA >>= f    = MemoryM $ \ runner -> do a <- unMemoryM memA runner
                                           unMemoryM (f a) runner

instance MonadIO MemoryM where
  liftIO io = MemoryM $ \ _ -> io
  -- Beware: do not follow the hlint suggestion. The ugly definition
  -- is to avoid usage of impredicative polymorphism.

instance MonadMemory MemoryM  where

  securely   mem = unMemoryM mem securely
  insecurely mem = unMemoryM mem insecurely


-- | Run the memory thread to obtain a memory action.
runMT :: Memory mem => MT mem a -> MemoryM a
runMT mem = MemoryM $ \ runner -> runner mem

------------------------ A memory allocator -----------------------


type AllocField = Field Pointer

-- | A memory allocator for the memory type @mem@. The `Applicative`
-- instance of @Alloc@ can be used to build allocations for
-- complicated memory elements from simpler ones.
type Alloc mem = TwistRF AllocField ALIGN mem

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
-- >    memoryAlloc   = (,) <$> memoryAlloc <*> memoryAlloc
-- >
-- >    underlyingPtr (ma, _) =  underlyingPtr ma
--
class Memory m where

  -- | Returns an allocator for this memory.
  memoryAlloc    :: Alloc m

  -- | Returns the pointer to the underlying buffer.
  underlyingPtr  :: m -> Pointer

instance ( Memory ma, Memory mb ) => Memory (ma, mb) where
    memoryAlloc           = (,) <$> memoryAlloc <*> memoryAlloc
    underlyingPtr (ma, _) =  underlyingPtr ma

instance ( Memory ma
         , Memory mb
         , Memory mc
         )
         => Memory (ma, mb, mc) where
    memoryAlloc           = (,,)
                            <$> memoryAlloc
                            <*> memoryAlloc
                            <*> memoryAlloc
    underlyingPtr (ma,_,_) =  underlyingPtr ma

instance ( Memory ma
         , Memory mb
         , Memory mc
         , Memory md
         )
         => Memory (ma, mb, mc, md) where
    memoryAlloc           = (,,,)
                            <$> memoryAlloc
                            <*> memoryAlloc
                            <*> memoryAlloc
                            <*> memoryAlloc

    underlyingPtr (ma,_,_,_) =  underlyingPtr ma

-- | Copy data from a given memory location to the other. The first
-- argument is destionation and the second argument is source to match
-- with the convention followed in memcpy.
copyMemory :: Memory m => Dest m -- ^ Destination
                       -> Src  m -- ^ Source
                       -> IO ()
copyMemory dmem smem = memcpy (underlyingPtr <$> dmem) (underlyingPtr <$> smem) sz
  where sz       = twistMonoidValue $ getAlloc smem
        getAlloc :: Memory m => Src m -> Alloc m
        getAlloc _ = memoryAlloc

-- | Perform an action which makes use of this memory. The memory
-- allocated will automatically be freed when the action finishes
-- either gracefully or with some exception. Besides being safer,
-- this method might be more efficient as the memory might be
-- allocated from the stack directly and will have very little GC
-- overhead.
withMemory   :: Memory m => (m -> IO a) -> IO a
withMemory   = withM memoryAlloc
  where withM :: Memory m => Alloc m -> (m -> IO a) -> IO a
        withM alctr action = allocaBuffer sz actualAction
          where sz                 = twistMonoidValue alctr
                getM               = computeField $ twistFunctorValue alctr
                wipeIt cptr        = memset cptr 0 sz
                actualAction  cptr = action (getM cptr) <* wipeIt cptr


-- | Similar to `withMemory` but allocates a secure memory for the
-- action. Secure memories are never swapped on to disk and will be
-- wiped clean of sensitive data after use. However, be careful when
-- using this function in a child thread. Due to the daemonic nature
-- of Haskell threads, if the main thread exists before the child
-- thread is done with its job, sensitive data can leak. This is
-- essentially a limitation of the bracket which is used internally.
withSecureMemory :: Memory m => (m -> IO a) -> IO a
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
modify :: (Initialisable m a, Extractable m b) =>  (b -> a) -> MT m ()
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
          allocator b = makeAlloc (byteSize b) $ MemoryCell . castPtr

  underlyingPtr  = castPtr . unMemoryCell

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = execute $ flip poke a . unMemoryCell
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = execute $ peek . unMemoryCell
  {-# INLINE extract #-}

instance EndianStore a => InitialisableFromBuffer (MemoryCell a) where
  initialiser  = readInto 1 . destination . unMemoryCell

instance EndianStore a => ExtractableToBuffer (MemoryCell a) where
  extractor  = writeFrom 1 . source . unMemoryCell
