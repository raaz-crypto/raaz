{-|

The memory subsystem associated with raaz.

-}

{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Core.Memory
       (
       -- * The Memory subsystem
       -- $memorysubsystem$

       -- ** Memory monads
         MonadMemory(..)
       , MT, execute, getMemory, liftSubMT
       , MemoryM, runMT
       -- *** Some low level functions.
       , getMemoryPointer, withPointer
       , allocate
       -- ** Memory elements.
       , Memory(..), copyMemory
       , Initialisable(..), Extractable(..), modify
       -- *** Some basic memory elements.
       , MemoryCell
       -- ** Memory allocation
       ,  Alloc, pointerAlloc
       ) where

import           Control.Applicative
import           Control.Monad.IO.Class
import           Data.Monoid (Sum (..))
import           Foreign.Storable(Storable(..))
import           Foreign.Ptr (castPtr)
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types

-- $memorysubsystem$
--
-- The memory subsystem consists of two main components.
--
-- 1. Abstract elements captured by the `Memory` type class.
--
-- 2. Abstract memory actions captured by the type class `MonadMemory`.
--

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
  fmap f mem = MemoryM $ \ runner -> fmap f $ unMemoryM mem runner

instance Applicative MemoryM where
  pure  x       = MemoryM $ \ _ -> return x
  memF <*> memA = MemoryM $ \ runner ->  unMemoryM memF runner <*> unMemoryM memA runner

instance Monad MemoryM where
  return = pure
  memA >>= f    = MemoryM $ \ runner -> do a <- unMemoryM memA runner
                                           unMemoryM (f a) runner

instance MonadIO MemoryM where
  liftIO io = MemoryM $ \ _ -> io

instance MonadMemory MemoryM  where

  securely   mem = unMemoryM mem $ securely
  insecurely mem = unMemoryM mem $ insecurely


-- | Run the memory thread to obtain a memory action.
runMT :: Memory mem => MT mem a -> MemoryM a
runMT mem = MemoryM $ \ runner -> runner mem

------------------------ A memory allocator -----------------------

type ALIGNMonoid = Sum ALIGN

type AllocField = Field Pointer

-- | A memory allocator for the memory type @mem@. The `Applicative`
-- instance of @Alloc@ can be used to build allocations for
-- complicated memory elements from simpler ones.
type Alloc mem = TwistRF AllocField ALIGNMonoid mem

-- | Make an allocator for a given memory type.
makeAlloc :: LengthUnit l => l -> (Pointer -> mem) -> Alloc mem
makeAlloc l memCreate = TwistRF (WrapArrow memCreate) (Sum $ atLeast l)

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

class Memory m => Initialisable m v where
  initialise :: v -> MT m ()

class Memory m => Extractable m v where
  extract  :: MT m v

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
copyMemory :: Memory m => m -- ^ Destination
                       -> m -- ^ Source
                       -> IO ()
copyMemory dest src = memcpy (underlyingPtr dest) (underlyingPtr src) sz
  where sz = getSum $ twistMonoidValue $ getAlloc src
        getAlloc :: Memory m => m -> Alloc m
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

--------------------- Some instances of Memory --------------------

-- | A memory location to store a value of type having `Storable`
-- instance.
newtype MemoryCell a = MemoryCell { unMemoryCell :: Pointer }


-- | Perform some pointer action on MemoryCell. Useful while working
-- with ffi functions.
withCell :: (Pointer -> IO b) -> MT (MemoryCell a) b
withCell fp  = execute $ fp . unMemoryCell
{-# INLINE withCell #-}

-- | Apply the given function to the value in the cell.
modify :: (Initialisable m a, Extractable m b) =>  (b -> a) -> MT m ()
modify f = extract >>= initialise . f

instance Storable a => Memory (MemoryCell a) where

  memoryAlloc = allocator undefined
    where allocator :: Storable b => b -> Alloc (MemoryCell b)
          allocator b = makeAlloc (byteSize b) MemoryCell

  underlyingPtr (MemoryCell cptr) = cptr

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = withCell (flip poke a . castPtr)
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = withCell (peek . castPtr)
  {-# INLINE extract #-}
