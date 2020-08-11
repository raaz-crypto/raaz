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
{-# LANGUAGE RecordWildCards            #-}
module Raaz.Core.Memory
       (

         -- BANNED combinators
         --
         -- 1. copyMemory

       -- $memorysubsystem$

       -- * The memory class

         Alloc, Memory(..)
       , VoidMemory, withMemoryPtr
       , withMemory, withSecureMemory
       , pointerAlloc

       -- * Initialisation and Extraction.
       -- $init-extract$

       , Initialisable(..), Extractable(..), modifyMem
       , Access(..), Accessible(..), copyAccessible, accessReader, accessWriter
       , unsafeCopyToAccess, unsafeCopyFromAccess

       -- * A basic memory cell.
       , MemoryCell, withCellPointer, getCellPointer

       ) where

import           Foreign.Ptr                 ( castPtr, Ptr )
import           Foreign.Storable            ( Storable )
import qualified Data.List             as List

import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types    hiding   ( zipWith       )
import           Raaz.Core.Types.Copying     ( unDest, unSrc )
import           Raaz.Core.Transfer.Unsafe
-------------- BANNED FEATURES ---------------------------------------
--
-- This module has a lot of low level pointer gymnastics and hence
-- should be dealt with care. The following features are BANNED
-- and hence should never be exposed. Often they are subtle and can
-- be easily missed. Hence it is documented here.
--
-- * COPY BUG
--
-- ** Combinator:
--
-- >
-- > `copyMemory :: Memory mem => Dest mem -> Src mem -> IO ()
-- >
--
-- ** THE BUG. At first it looks like a useful, general function to
-- have which is just a memcpy on the underlying pointers. For a
-- memory element we can easily get its pointer and size. However this
-- has a very subtle bug. The actual data in certain memory elements
-- like MemoryCell's have a runtime dependent offset from its raw
-- pointer and can defer from one element to another. As an example
-- consider two MemoryCells A and B of type `MemoryCell Word64` and
-- let us assume that the alignment restriction for both these is
-- 8-byte boundary. The Allocation strategy for MemoryCell is the following.
--
-- (1) The size is 16 (using the atleastAligned function)
-- (2) The starting pointer is the next 8-byte aligned pointer from the
--     given pointer.
--
-- It is very well possible that on allocation A gets an 8-byte
-- aligned memory pointer internally and the nextAligned pointer would
-- be itself. However, B might not be aligned and hence the actual
-- pointer for B might have a non-zero offset from its raw
-- pointer. Clearly a memcpy from the associated raw pointers will
-- mean that the initial segment of A is lost to B.




-- $memorysubsystem$
--
-- The memory subsytem of raaz is captured by the `Memory` class which
-- intern has an `Alloc` strategy. The goal of this module is to give
-- a relatively abstract interface to these that hides the low level
-- size calculation and pointer arithmetic.


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

-- $init-extract$
--
-- Memories often allow initialisation with and extraction of values
-- in the Haskell world. The `Initialisable` and `Extractable` class
-- captures this interface. One should, however, refrain
-- initialising/extracting sensitive values as such values reside in
-- the Haskell heap which is not locked and are often relocated during
-- garbage collection phases.
--
-- Protocols often need to setup a key in a particular memory cell and
-- then use that key for say encryption.  To handle such cases,
-- certain memory elements provide an `Access` into its memory
-- pointer.  Writing into and reading from these can then be achieved
-- by using memcpy.

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



-- | An access into a memory is a buffer that points to the actual
-- data together with an endian adjustment action. If data needs to be
-- transferred to the outside world, or bytes are to be read from the
-- outside world, the accessAdjust action should be run.
data Access = Access { accessPtr    :: Ptr Word8
                     , accessSize   :: BYTES Int
                     , accessAdjust :: IO ()
                     }

-- | The reader action that reads bytes from the input buffer to the
-- access buffer.
accessReader :: Access -> ReadFrom
accessReader Access{..}
  = unsafeReadIntoPtr accessSize (destination accessPtr)
    <> unsafeInterleave accessAdjust

-- | The writer action that writes into input buffer from the access
-- buffer.
accessWriter :: Access -> WriteTo
accessWriter Access{..}  = unsafeInterleave accessAdjust
                           <> unsafeWriteFromPtr accessSize (source accessPtr)
                           <> unsafeInterleave accessAdjust

-- | Fill the access buffer from a source pointer. This function is unsafe because
-- it does not check whether there is enough data on the source side.
unsafeCopyToAccess :: Access
                   -> Src (Ptr a)
                   -> IO ()
unsafeCopyToAccess acc sptr = do
  memcpy dptr sptr sz
  accessAdjust acc
  where sz   = accessSize acc
        dptr = destination $ accessPtr acc

unsafeCopyFromAccess :: Dest (Ptr a)
                     -> Access
                     -> IO ()
unsafeCopyFromAccess dptr acc = do
  accessAdjust acc    -- adjust before transfer
  memcpy dptr sptr sz
  accessAdjust acc    -- adjust it back after completion.
  where sz   = accessSize acc
        sptr = source $ accessPtr acc


-- | Memories that have an access mechanism.
class Memory mem => Accessible mem where
  -- | Get access into the memory's buffer. Instances should ensure
  -- the following.
  --
  -- 1. The number of elements in the access list  and,
  -- 2. The sizes of each element in the access lists
  --
  -- should be independent of the value stored in the memory. All the
  -- basic memory elements exposed from raaz library satisfy the above
  -- property. Any other memory element of interest are products of
  -- such simple memory element and hence a concatenation of their
  -- access list will satisfy the property.
  accessList :: mem -> [Access]

-- | This action is only available for accessible memory not general memories.
copyAccessible :: Accessible mem => Dest mem -> Src mem -> IO ()
copyAccessible dest src = sequence_ $ List.zipWith cp dAlist sAlist
  -- NOTE: no adjustment is needs as both contain values of the same
  -- type.
    where dAlist = map destination $ accessList $ unDest dest
          sAlist = map source      $ accessList $ unSrc  src
          cp   :: Dest Access -> Src Access -> IO ()
          cp dA sA = memcpy dptr sptr sz
            where sz   = accessSize $ unDest dA
                  dptr = accessPtr <$> dA
                  sptr = accessPtr <$> sA

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

instance EndianStore a => Accessible (MemoryCell a) where
  accessList mem = [ Access { accessPtr    = castPtr bufPtr
                            , accessSize   = sz
                            , accessAdjust = adjustEndian bufPtr 1
                            }
                   ]
    where getProxy   :: MemoryCell a -> Proxy a
          getProxy _ =  Proxy
          sz         = sizeOf $ getProxy mem
          bufPtr     = getCellPointer mem
