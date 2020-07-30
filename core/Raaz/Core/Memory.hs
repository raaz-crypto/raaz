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
         Memory(..), withMemory, withSecureMemory,
         VoidMemory, copyMemory, withMemoryPtr
       -- *** Initialisation and Extraction.
       -- $init-extract$
       , Initialisable(..), Extractable(..), modifyMem
       , InitialisableFromBuffer(..), ExtractableToBuffer(..)
       -- *** A basic memory cell.
       , MemoryCell, withCellPointer, getCellPointer
       -- ** Memory allocation
       ,  Alloc, pointerAlloc
       ) where

import           Foreign.Storable            ( Storable )
import           Foreign.Ptr                 ( castPtr, Ptr )
import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Transfer
import           Raaz.Core.Types

------------------------ A memory allocator -----------------------


type AllocField = Field (Ptr Word8)

-- | A memory allocator for the memory type @mem@. The `Applicative`
-- instance of @Alloc@ can be used to build allocations for
-- complicated memory elements from simpler ones.
type Alloc mem = TwistRF AllocField (BYTES Int) mem

-- | Make an allocator for a given memory type.
makeAlloc :: LengthUnit l => l -> (Ptr Word8 -> mem) -> Alloc mem
makeAlloc l memCreate = TwistRF (WrapArrow memCreate) $ atLeast l

-- | Allocates a buffer of size @l@ and returns the pointer to it pointer.
pointerAlloc :: LengthUnit l => l -> Alloc (Ptr Word8)
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
  unsafeToPointer :: m -> Ptr Word8


-- | A memory element that holds nothing.
newtype VoidMemory = VoidMemory { unVoidMemory :: Ptr Word8  }

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
-- argument is destination and the second argument is source to match
-- with the convention followed in memcpy.
copyMemory :: Memory m => Dest m -- ^ Destination
                       -> Src  m -- ^ Source
                       -> IO ()
copyMemory dmem smem = memcpy (unsafeToPointer <$> dmem) (unsafeToPointer <$> smem) sz
  where sz       = twistMonoidValue $ getAlloc smem
        getAlloc :: Memory m => Src m -> Alloc m
        getAlloc _ = memoryAlloc

-- | Apply some low level action on the underlying buffer of the
-- memory.
withMemoryPtr :: Memory m
              => (BYTES Int -> Ptr Word8 -> IO a)
              -> m -> IO a
withMemoryPtr action mem = action sz $ unsafeToPointer mem
  where sz = twistMonoidValue $ getAlloc mem
        getAlloc :: Memory m => m -> Alloc m
        getAlloc _ = memoryAlloc

-- | Perform an action which makes use of this memory. The memory
-- allocated will automatically be freed when the action finishes
-- either gracefully or with some exception. Besides being safer,
-- this method might be more efficient as the memory might be
-- allocated from the stack directly and will have very little GC
-- overhead.
withMemory   :: Memory mem => (mem -> IO a) -> IO a
withMemory   = withM memoryAlloc
  where withM :: Alloc mem -> (mem -> IO a) -> IO a
        withM alctr action = allocaBuffer sz actualAction
          where sz                 = twistMonoidValue alctr
                getM               = computeField $ twistFunctorValue alctr
                wipeIt cptr        = wipeMemory cptr sz
                actualAction  cptr = action (getM cptr) <* wipeIt cptr


-- | Similar to `withMemory` but allocates a secure memory for the
-- action. Secure memories are never swapped on to disk and will be
-- wiped clean of sensitive data after use. However, be careful when
-- using this function in a child thread. Due to the daemonic nature
-- of Haskell threads, if the main thread exists before the child
-- thread is done with its job, sensitive data can leak. This is
-- essentially a limitation of the bracket which is used internally.
withSecureMemory :: Memory mem => (mem -> IO a) -> IO a
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
  initialise :: v -> m -> IO ()

-- | Memories from which pure values can be extracted. Once a pure value is
-- extracted,
class Memory m => Extractable m v where
  extract  :: m -> IO v


-- | Apply the given function to the value in the cell. For a function @f :: b -> a@,
-- the action @modify f@ first extracts a value of type @b@ from the
-- memory element, applies @f@ to it and puts the result back into the
-- memory.
--
-- > modifyMem f mem = do b          <- extract mem
-- >                      initialise (f b) mem
--
modifyMem :: (Initialisable mem a, Extractable mem b) =>  (b -> a) -> mem -> IO ()
modifyMem f mem = extract mem >>= flip initialise mem . f

-- | A memory type that can be initialised from a pointer buffer. The initialisation performs
-- a direct copy from the input buffer and hence the chances of the
-- initialisation value ending up in the swap is minimised.
class Memory m => InitialisableFromBuffer m where
  initialiser :: m -> ReadIO

-- | A memory type that can extract bytes into a buffer. The extraction will perform
-- a direct copy and hence the chances of the extracted value ending
-- up in the swap space is minimised.
class Memory m => ExtractableToBuffer m where
  extractor :: m -> WriteIO

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
getCellPointer :: Storable a => MemoryCell a -> Ptr a
getCellPointer = nextLocation . unMemoryCell

-- | Work with the underlying pointer of the memory cell. Useful while
-- working with ffi functions.
withCellPointer :: Storable a => (Ptr a -> IO b) -> MemoryCell a -> IO b
{-# INLINE withCellPointer #-}
withCellPointer action = action . getCellPointer

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = flip pokeAligned a . unMemoryCell
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = peekAligned . unMemoryCell
  {-# INLINE extract #-}

instance EndianStore a => InitialisableFromBuffer (MemoryCell a) where
  initialiser  = readInto 1 . destination . getCellPointer

instance EndianStore a => ExtractableToBuffer (MemoryCell a) where
  extractor  = writeFrom 1 . source . getCellPointer
