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
       , Access(..), accessReader, accessWriter, unsafeClampAccess
       , unsafeCopyToAccess, unsafeCopyFromAccess
       , Accessible(..), copyConfidential
       , confidentialReader, confidentialWriter
       -- * A basic memory cell.
       , MemoryCell, withCellPointer, unsafeGetCellPointer

       ) where

import           Foreign.Ptr                 ( castPtr )
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

-- $access$
--
-- Transferring data from one memory to another can indeed be achieved
-- by the mechanism provided through the `Initialisable` and
-- `Extractable` type classes. However, such a transfer is done via a
-- pure value that is stored in the Haskell heap which can leak to a
-- disk during swapping. Furthermore, a generational GC moves a pure
-- value around making the chances of such a swap higher. The `Access`
-- data type provides an access into the raw bytes associated with the
-- memory elements. The `Accessible` type class captures instances of
-- memory which provide an access to the internal buffer.

-- | An access into a memory is a buffer that points to the actual
-- data together with an endian adjustment action. Before reading the
-- contents to the outside world, we might need to clamp certain bits
-- and adjust for endian mismatch . Similarly, after writing the
-- contents from the outside world, we might have adjust the endian
-- and then possibly clamp some bits. These action are captured by the
-- members `accessBeforeRead` and `accessAfterWrite` fields of this
-- record.

data Access = Access
  { accessPtr         :: Ptr Word8
    -- ^ The buffer pointer associated with this access.
  , accessSize        :: BYTES Int
    -- ^ The size of this access buffer.
  , accessBeforeRead  :: IO ()
    -- ^ Adjustments to be carried out on the buffer before reading from it.
  , accessAfterWrite :: IO ()
    -- ^ Adjustment to be carried out on the buffer after writing.
  }

-- | Often we need to add some clamping functions to the before read
-- and after write action. This function updates the access function
-- with clamping. Sane clamping functions should be idempotent.
unsafeClampAccess :: (Ptr a -> IO ()) -- ^ The clamping action (should be idempotent)
                  -> Access
                  -> Access
unsafeClampAccess clamp acc@Access{..}
  = acc { accessBeforeRead = clamp (castPtr accessPtr) >> accessBeforeRead
        , accessAfterWrite = accessAfterWrite >> clamp (castPtr accessPtr)
        }

-- | The reader action that reads from the input buffer and transfers
-- to the access buffer.
accessReader :: Access -> ReadFrom
accessReader Access{..}
  = unsafeReadIntoPtr accessSize (destination accessPtr)
    <> unsafeInterleave accessAfterWrite

-- | The writer action that writes into input buffer from the access
-- buffer.
accessWriter :: Access -> WriteTo
accessWriter Access{..}  = unsafeInterleave accessBeforeRead
                           <> unsafeWriteFromPtr accessSize (source accessPtr)
                           <> unsafeInterleave accessAfterWrite

-- | Fill the access buffer from a source pointer. This function is unsafe because
-- it does not check whether there is enough data on the source side.
unsafeCopyToAccess :: Access
                   -> Src (Ptr a)
                   -> IO ()
unsafeCopyToAccess acc sptr = do
  memcpy dptr sptr sz
  accessAfterWrite acc
  where sz   = accessSize acc
        dptr = destination $ accessPtr acc

-- | The action @unsafeCopyFromAccess dest acc@ copies data from @acc
-- : Access@ to the destination pointer dest. The function is unsafe
-- because it does not check whether the destination pointer has
-- enough size to receive data from the access.
unsafeCopyFromAccess :: Dest (Ptr a)
                     -> Access
                     -> IO ()
unsafeCopyFromAccess dptr acc = do
  accessBeforeRead acc    -- adjust before transfer
  memcpy dptr sptr sz
  accessAfterWrite acc    -- adjust it back after completion.
  where sz   = accessSize acc
        sptr = source $ accessPtr acc


-- | Memories with an access mechanism given by the member
-- `confidentialAccess`. Instances should satisfy the following
-- properties.
--
-- 1. Instances should ensure that the number of elements in this list
-- and their individual sizes are only dependent on the type `mem` and
-- not the actual value stored. Moreover, the endian adjustment should
-- not be needed when copying between the corresponding accesses.
--
-- 2. Each of the elements in the `confidentialAccess` should give
-- access to non-overlapping sections of the buffer associated with
-- the memory. As a corollary, the total size of this list of accesses
-- should be less than the allocation size for the given memory.
--
-- Only those portions of the memory that are critical for the safety
-- need to be represented in the list. For example, in the memory
-- associated with a cipher, only the portion that stores the key and
-- not the nounce need to be included in the nounce list.
--
class Memory mem => Accessible mem where
  -- | The list of confidential accesses into the buffer associated
  -- with the memory element.
  confidentialAccess :: mem -> [Access]

-- | This action is only available for accessible memory not general memories.
copyConfidential :: Accessible mem => Dest mem -> Src mem -> IO ()
copyConfidential dest src = sequence_ $ List.zipWith cp dAlist sAlist
  -- NOTE: no adjustment is needs as both contain values of the same
  -- type.
    where dAlist = map destination $ confidentialAccess $ unDest dest
          sAlist = map source      $ confidentialAccess $ unSrc  src
          cp   :: Dest Access -> Src Access -> IO ()
          cp dA sA = memcpy dptr sptr sz
            where sz   = accessSize $ unDest dA
                  dptr = accessPtr <$> dA
                  sptr = accessPtr <$> sA

-- | Get a reader that reads into the memory through its confidential
-- access.
confidentialReader :: Accessible mem => mem -> ReadFrom
confidentialReader = mconcat . map accessReader . confidentialAccess


-- | Get a Writer that writes out from the memory through its
-- confidential access.
confidentialWriter :: Accessible mem => mem -> WriteTo
confidentialWriter = mconcat . map accessWriter . confidentialAccess

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

instance Storable a => Initialisable (MemoryCell a) a where
  initialise a = flip pokeAligned a . unMemoryCell
  {-# INLINE initialise #-}

instance Storable a => Extractable (MemoryCell a) a where
  extract = peekAligned . unMemoryCell
  {-# INLINE extract #-}

instance EndianStore a => Accessible (MemoryCell a) where
  confidentialAccess mem = [ Access { accessPtr    = castPtr bufPtr
                                    , accessSize   = sz
                                    , accessBeforeRead = adjustEndian bufPtr 1
                                    , accessAfterWrite = adjustEndian bufPtr 1
                                    }
                           ]
    where getProxy   :: MemoryCell a -> Proxy a
          getProxy _ =  Proxy
          sz         = sizeOf $ getProxy mem
          bufPtr     = unsafeGetCellPointer mem
