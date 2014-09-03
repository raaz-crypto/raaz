{-|

The internals of the memory subsystem. This module provides utility
functions to work with secure memory. By secure memory, we mean memory
that will /not/ be swapped out to the external disk. It is recommended
to use secure memory to store sensitive information like pass-phrase,
especially in an environment where there are hostile users on the same
system. However, using secure memory alone is not really going to save
the day.

Operating systems have limit on the amount of memory that can be
locked by a users process. So use it judiciously.

-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE TupleSections              #-}

module Raaz.Core.Memory.Internal
       (
         -- * Architecture of the allocator.
         -- $architecture
         PAGES (..)
         -- PoolRef helper functions
       , PoolRef
       , allocSecureMem
       , initPoolRef
       , freeSecureMem
       , withSecureMem
       ) where

import           Control.Arrow          (first)
import           Control.Exception      (finally)
import           Data.IORef
import           Data.Traversable       (traverse)
import           Foreign.Concurrent
import           Foreign.ForeignPtr     (finalizeForeignPtr)

import           Raaz.System.Parameters (pageSize)
import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr

foreign import ccall unsafe "cbits/raaz/memory.c memorylock"
  c_mlock :: CryptoPtr -> Int -> IO Int

foreign import ccall unsafe "cbits/raaz/memory.c memoryunlock"
  c_munlock :: CryptoPtr -> Int -> IO ()

foreign import ccall unsafe "cbits/raaz/memory.c createpool"
  c_createpool :: Int -> IO CryptoPtr

foreign import ccall unsafe "cbits/raaz/memory.c freepool"
  c_freepool :: CryptoPtr -> Int -> IO ()

foreign import ccall unsafe "cbits/raaz/memory.c wipememory"
  c_wipe :: CryptoPtr -> Int -> IO ()

-- $architecture
--
-- We describe the architecture of the secure memory allocation
-- system. Memory is allocated as a `ForeignPtr` and finalizers are
-- set that will wipe the memory with zeros before de-allocation.  The
-- memory is allocated in units of pages as most operating systems
-- support only locking of an entire page. We call this a pool
-- captured by the data type `Pool`. During the course of allocation
-- this pool gets fragmented into blocks. Therefore, a pool is
-- essentially a list of blocks (captured by the `Block` data type)
-- together with some meta information. Finally we have the
-- `PoolRef` which keeps track fo all the pools in a `IORef`.
--


-- | Captures the state of secure memory and allows modification in a
-- thread safe way.
type PoolRef = IORef Pool



-- | Captures the pool of secure memory. Whenever a new secure memory
-- is needed, it is allocated from this pool. Reference to
-- `ForeignPtr` is kept to prevent it from being garbage collected.
data Pool = Pool ForeignCryptoPtr  -- Location
                 PAGES             -- Total Size
                 [Block]           -- Blocks inside pool

-- | A block of allocated secure memory in a pool.
data Block = Block { blockPtr    :: CryptoPtr         -- Location
                   , blockSize   :: BYTES Int         -- Size
                   , blockIsFree :: Bool              -- isFree
                   }

-- | Allocates the memory from the secure pool and returns the
-- allocated `CryptoPtr`. In case of unavailability of enough free
-- space, returns Nothing.
allocFromPool :: LengthUnit size
              => size
              -> Pool
              -> (Pool, Maybe CryptoPtr)
allocFromPool size (Pool fp sz blks) = first (Pool fp sz)
                                     $ getFreeBlock blks
  where
    bsize = inBytes size
    -- TODO: Refactor getFreeBlock using span
    getFreeBlock [] = ([], Nothing)
    getFreeBlock (b@(Block p s f):rs)
      | bsize < s && f =
          let lb = Block p bsize False
              rb = Block (movePtr p bsize) (s - bsize) True
          in (lb:rb:rs,Just p)
      | bsize == s && f =
          let lb = Block p bsize False
          in (lb:rs,Just p)
      | otherwise = first (b:) $ getFreeBlock rs

-- | It frees the block associated with the @ptr@ by marking it free
-- in the pool. It also merges adjacent free blocks.
freeInPool :: CryptoPtr
           -> Pool
           -> Pool
freeInPool ptr (Pool fp sz blks) =
    Pool fp sz $ sweep $ mark blks
  where
    mark [] = blks
    mark (b:bs) | blockPtr b == ptr = b {blockIsFree = True} : bs
                | otherwise         = b : mark bs
    sweep = foldr with []
    with l [] = [l]
    with l visited@(r:rs) | blockIsFree l && blockIsFree r = merge l r : rs
                          | otherwise                      = l : visited
    merge b1 b2 = b1 {blockSize = blockSize b1 + blockSize b2}

-- | Creates the initial pool of secure memory of the given size. It
-- also adds the finalizer to wipe and unlock the memory.
initPool :: LengthUnit size
         => size
         -> IO Pool
initPool size  = do
  let pg  = atLeast  size   :: PAGES
      by@(BYTES psize) = inBytes pg
  ptr <- c_createpool psize
  out <- c_mlock ptr psize
  if out < 0 then fail "mlock_fail"
    else do
    fptr <- newForeignPtr ptr $ return ()
    addFinalizers fptr [ c_freepool ptr psize
                       , c_munlock ptr psize
                       , c_wipe ptr psize
                       ]
    return (Pool fptr pg [Block ptr by True])
  where
    addFinalizers :: ForeignCryptoPtr -> [IO ()] -> IO ()
    addFinalizers fptr = mapM_ (addForeignPtrFinalizer fptr)

-- | Creates the initial `PoolRef` with the pool of given size.
initPoolRef :: LengthUnit size
               => size
               -> IO PoolRef
initPoolRef size = newIORef =<< initPool size

-- | Allocates the `ForeignCryptoPtr` from the already available pool
-- of secure memory. Also adds the finalizer to mark the block as free
-- in the `PoolRef`. Returns `Nothing` if enough free memory is not
-- available in the pool.
allocSecureMem :: LengthUnit size
               => size
               -> PoolRef
               -> IO (Maybe ForeignCryptoPtr)
allocSecureMem size bkpr = atomicModifyIORef bkpr (allocFromPool size)
                         >>= traverse createFptr
  where
    createFptr cptr = newForeignPtr cptr $ freeSecureMem cptr bkpr

-- | Marks the associated block as free. This will rarely be used as
-- you can directly run the finalizer associated with the
-- `ForeignCryptoPtr`.
freeSecureMem :: CryptoPtr
              -> PoolRef
              -> IO ()
freeSecureMem cptr poolref = atomicModifyIORef poolref $ (,()) . freeInPool cptr

-- | Runs the action after allocating a secure memory of given size.
withSecureMem :: LengthUnit size
              => size                        -- ^ Size
              -> (ForeignCryptoPtr -> IO b)  -- ^ Action
              -> PoolRef                     -- ^ Pool
              -> IO b
withSecureMem sz action pool = allocSecureMem sz pool
                             >>= maybe (fail "SecureMemory Exhausted") runAction
  where
    runAction mem = finally (action mem) $ finalizeForeignPtr mem

--------------------- Pages -------------------------------------

-- | Type safe unit for measuring lengths in pages. Size is actually
-- system dependent.
newtype PAGES = PAGES Int deriving ( Show, Enum, Real
                                   , Integral, Num, Eq, Ord
                                   )

instance LengthUnit PAGES where
  inBytes (PAGES x) = BYTES $ pgSz * x
    where BYTES pgSz = pageSize
