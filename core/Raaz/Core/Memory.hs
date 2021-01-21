-- |
--
-- Module      : Raaz.Core.Memory
-- Description : Explicit, typesafe, low-level memory management in raaz
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

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


         -- * Low level memory management in raaz.
         -- $memorysubsystem$

         -- ** The memory class
         Memory(..)
       , VoidMemory, withMemoryPtr
       , withMemory, withSecureMemory
         -- ** The allocator
       , Alloc
       , pointerAlloc

       -- * Initialisation and Extraction.
       -- $init-extract$

       , Initialisable(..), Extractable(..), modifyMem

       -- * Accessing the bytes directly
       -- $access$
       --
       , Access(..)
       , ReadAccessible(..), WriteAccessible(..), memTransfer
       -- * A basic memory cell.
       , MemoryCell, copyCell, withCellPointer, unsafeGetCellPointer

       ) where

import           Foreign.Ptr                 ( castPtr )
import           Foreign.Storable            ( Storable )


import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types    hiding   ( zipWith       )
import           Raaz.Core.Types.Internal

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
-- __Warning:__ This module is pretty low level and should not be
-- needed in typical use cases. Only developers of protocols and
-- primitives might have a reason to look into this module.
--
-- The memory subsytem of raaz gives a relatively abstract and type
-- safe interface for performing low level size calculations and
-- pointer arithmetic. The two main components of this subsystem
-- is the class `Memory` whose instances are essentially memory buffers that
-- are distinguished at the type level, and the type `Alloc` that captures
-- the allocation strategies for these types.
--

------------------------ A memory allocator -----------------------

type AllocField = Field (Ptr Word8)

-- | A memory allocator for the memory type @mem@. The `Applicative`
-- instance of @Alloc@ can be used to build allocations for
-- complicated memory elements from simpler ones and takes care of
-- handling the size/offset calculations involved.
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
-- captures this interface.
--
-- == Explicit Pointer
--
-- Using the `Initialisable` and `Extractable` for sensitive data
-- interface defeats one important purpose of the memory subsystem
-- namely providing memory locking. Using these interfaces means
-- keeping the sensitive information as pure values in the Haskell
-- heap which impossible to lock. Worse still, the GC often move the
-- data around spreading it all around the memory. One should use
-- direct byte transfer via `memcpy` for effecting these
-- initialisation. An interface to facilitate these is the type
-- classes `ReadAccessible` and `WriteAccessble` where direct access
-- is given (via the `Access` buffer) to the portions of the internal
-- memory where sensitive data is kept.

-- | Memories that can be initialised with a pure value. The pure
-- value resides in the Haskell heap and hence can potentially be
-- swapped. Therefore, this class should be avoided if compromising
-- the initialisation value can be dangerous. Look into the type class
-- `WriteAccessible` instead.
class Memory m => Initialisable m v where
  initialise :: v -> m -> IO ()

-- | Memories from which pure values can be extracted. Much like the
-- case of the `Initialisable` class, avoid using this interface if
-- you do not want the data extracted to be swapped. Use the
-- `ReadAccessible` class instead.
class Memory m => Extractable m v where
  extract  :: m -> IO v


-- | Apply the given function to the value in the cell. For a function
-- @f :: b -> a@, the action @modify f@ first extracts a value of type
-- @b@ from the memory element, applies @f@ to it and puts the result
-- back into the memory.
--
-- > modifyMem f mem = do b <- extract mem
-- >                      initialise (f b) mem
--
modifyMem :: (Initialisable mem a, Extractable mem b) =>  (b -> a) -> mem -> IO ()
modifyMem f mem = extract mem >>= flip initialise mem . f

-- $access$
--
-- To avoid the problems associated with the `Initialisable` and
-- `Extractable` interface, certain memory types give access to the
-- associated buffers directly via the `Access` buffer. Data then
-- needs to be transferred between these memories directly via
-- `memcpy` making use of the `Access` buffers thereby avoiding a copy
-- in the Haskell heap where it is prone to leak.
--
-- [`ReadAccessible`:] Instances of these class are memories that are
-- on the source side of the transfer. Examples include the memory
-- element that is used to implement a Diffie-Hellman key
-- exchange. The exchanged key is in the memory which can then be used
-- to initialise a cipher for the actual transfer of encrypted data .
--
-- [`WriteAccessible`:] Instances of these classes are memories that
-- are on the destination side of the transfer. The memory element
-- that stores the key for a cipher is an example of such a element.

-- | Data type that gives an access buffer to portion of the memory.
data Access = Access
  { accessPtr         :: Ptr Word8
    -- ^ The buffer pointer associated with this access.
  , accessSize        :: BYTES Int
    -- ^ Its size
  }

-- | Transfer the bytes from the source memory to the destination
-- memory. The total bytes transferred is the minimum of the bytes
-- available at the source and the space available at the destination.
memTransfer :: (ReadAccessible src, WriteAccessible dest)
            => Dest dest
            -> Src src
            -> IO ()
memTransfer dest src = do
  let dmem = unDest dest
      smem = unSrc src
      in do beforeReadAdjustment smem
            copyAccessList (writeAccess dmem) (readAccess smem)
            afterWriteAdjustment dmem


-- | Copy access list, Internal function.
copyAccessList :: [Access] -> [Access] -> IO ()
copyAccessList (da:ds) (sa:ss)
  | dsize > ssize = tAct >> copyAccessList (da' : ds) ss
  | ssize > dsize = tAct >> copyAccessList ds         (sa' : ss)
  | otherwise     = tAct >> copyAccessList ds ss
    where dsize = accessSize da
          ssize = accessSize sa
          trans = min dsize ssize
          dptr  = accessPtr da
          sptr  = accessPtr sa
          da'   = Access (accessPtr da `movePtr` trans) (dsize - trans)
          sa'   = Access (accessPtr sa `movePtr` trans) (ssize - trans)
          tAct  = memcpy (destination dptr) (source sptr) trans
copyAccessList _ _ = return ()

-- | This class captures memories from which bytes can be extracted
-- directly from (portions of) its buffer.
class Memory mem => ReadAccessible mem where
  -- | Internal organisation of the data might need adjustment due to
  -- host machine having a different endian than the standard byte
  -- order of the associated type. This action perform the necessary
  -- adjustment before the bytes can be read-off from the associated
  -- `readAccess` adjustments.
  beforeReadAdjustment :: mem -> IO ()

  -- | The ordered access buffers for the memory through which bytes
  -- may be read off (after running `beforeReadAdjustment` of course)
  readAccess :: mem -> [Access]

-- | This class captures memories that can be initialised by writing
-- bytes to (portions of) its buffer.
class Memory mem => WriteAccessible mem where

  -- | The ordered access to buffers through which bytes may be
  -- written into the memory.
  writeAccess :: mem -> [Access]

  -- | After writing data into the buffer, the memory might need
  -- further adjustments before it is considered "initialised" with
  -- the sensitive data.
  --
  afterWriteAdjustment :: mem -> IO ()

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
unsafeGetCellPointer :: Storable a => MemoryCell a -> Ptr a
unsafeGetCellPointer = nextLocation . unMemoryCell

-- | Work with the underlying pointer of the memory cell. Useful while
-- working with ffi functions.
withCellPointer :: Storable a => (Ptr a -> IO b) -> MemoryCell a -> IO b
{-# INLINE withCellPointer #-}
withCellPointer action = action . unsafeGetCellPointer

-- | Copy the contents of one memory cell to another.
copyCell :: Storable a => Dest (MemoryCell a) -> Src (MemoryCell a) -> IO ()
copyCell dest src = memcpy (unsafeGetCellPointer <$> dest) (unsafeGetCellPointer <$> src) sz
  where getProxy :: Dest (MemoryCell a) -> Proxy a
        getProxy _ = Proxy
        sz = sizeOf (getProxy dest)

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = flip pokeAligned a . unMemoryCell
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = peekAligned . unMemoryCell
  {-# INLINE extract #-}

instance EndianStore a => ReadAccessible (MemoryCell a) where
  beforeReadAdjustment mem = adjustEndian (unsafeGetCellPointer mem) 1
  readAccess mem = [ Access { accessPtr    = castPtr bufPtr
                            , accessSize   = sz
                            }
                   ]
    where getProxy   :: MemoryCell a -> Proxy a
          getProxy _ =  Proxy
          sz         = sizeOf $ getProxy mem
          bufPtr     = unsafeGetCellPointer mem


instance EndianStore a => WriteAccessible (MemoryCell a) where
  writeAccess mem = [ Access { accessPtr    = castPtr bufPtr
                             , accessSize   = sz
                             }
                    ]
    where getProxy   :: MemoryCell a -> Proxy a
          getProxy _ =  Proxy
          sz         = sizeOf $ getProxy mem
          bufPtr     = unsafeGetCellPointer mem

  afterWriteAdjustment mem = adjustEndian (unsafeGetCellPointer mem) 1
