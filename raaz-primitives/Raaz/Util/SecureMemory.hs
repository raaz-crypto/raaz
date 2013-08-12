{-

This module provides utility functions to work with secure memory.

-}
{-# LANGUAGE FlexibleContexts         #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE MultiParamTypeClasses    #-}

module Raaz.Util.SecureMemory
       ( ForeignCryptoPtr
       , PAGES(..)
       , Block
       , Pool
         -- Pool helper functions
       , initPool
       , allocFromPool
       , freeInPool
         -- BookKeeper helper functions
       , BookKeeper
       , allocSecureMem
       , initBookKeeper
       , freeSecureMem
       , allocSecureMem'
       ) where

import Control.Arrow ( first )
import Control.Monad.State
import Data.IORef
import Foreign.ForeignPtr.Safe ( ForeignPtr
                               , finalizeForeignPtr
                               )
import Foreign.Concurrent
import Foreign.ForeignPtr.Unsafe

import Raaz.Types
import Raaz.Util.Ptr
import Raaz.System.Parameters ( pageSize )

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

-- | Captures word aligned `ForeignPtr`.
type ForeignCryptoPtr = ForeignPtr CryptoAlign

-- | Captures the pool of secure memory. Whenever a new secure memory
-- is needed, it is allocated from this pool. Reference to
-- `ForeignPtr` is kept to prevent it from being garbage collected.
data Pool = Pool ForeignCryptoPtr  -- Location
                 (PAGES Int)       -- Total Size
                 [Block]           -- Blocks inside pool

-- | Captures the state of secure memory and allows modification in a thread
-- safe way.
type BookKeeper = IORef [Pool]

-- | A block of allocated secure memory in a pool.
data Block = Block CryptoPtr         -- Location
                   (BYTES Int)       -- Size
                   Bool              -- isFree

-- | Captures memory in terms of number of pages
newtype PAGES a = PAGES a

instance ( Integral by
         , Num pg
         )
         => CryptoCoerce (BYTES by) (PAGES pg) where
  cryptoCoerce (BYTES by) | r == 0    = PAGES $ fromIntegral q
                          | otherwise = PAGES $ fromIntegral q + 1
    where (q,r) = (fromIntegral by) `quotRem` pageSize

instance ( Integral pg
         , Num by
         )
         => CryptoCoerce (PAGES pg) (BYTES by) where
  cryptoCoerce (PAGES pg) = BYTES $ (fromIntegral pg) * (fromIntegral pageSize)


-- | Allocates the memory from the secure pool and returns the
-- allocated `CryptoPtr`. In case of unavailability of enough free
-- space, returns Nothing.
allocFromPool :: CryptoCoerce size (BYTES Int)
              => size
              -> Pool
              -> (Pool,Maybe CryptoPtr)
allocFromPool size (Pool fp sz blks) = let (nblks,free) = getFreeBlock blks
                                     in (Pool fp sz nblks,free)
  where
    bsize = cryptoCoerce size
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

-- | Marks the block associated the pointer as free. Merges if
-- adjacent block is also free.
freeInPool :: CryptoPtr
           -> Pool
           -> Pool
freeInPool ptr (Pool fp sz blks) =
    Pool fp sz $ mergeZipper $ buildZipper ptr (blks,[])
  where
    buildZipper _ xs@([],_) = xs
    buildZipper cptr (b@(Block p s _):ls,rs)
      | p == cptr = ((Block p s True):ls,rs)
      | otherwise = buildZipper cptr (ls,b:rs)
    mergeZipper ([],rs) = rs
    mergeZipper ([b],(r1:rs)) = reverse (merge r1 [b] ++ rs)
    mergeZipper ((b:ls),[]) = merge b ls
    mergeZipper ((b:ls),(r1:rs)) = reverse rs ++ merge r1 (merge b ls)
    merge b [] = [b]
    merge b1@(Block p1 s1 f1) (b2@(Block _ s2 f2):rs)
      | f1 && f2 = (Block p1 (s1 + s2) True):rs
      | otherwise = b1:b2:rs

-- | Creates the initial pool of secure memory of the given size. It
-- also adds the finalizer to wipe and unlock the memory.
initPool :: CryptoCoerce size (BYTES Int)
         => size
         -> IO Pool
initPool size  = do
  let tby = cryptoCoerce size :: BYTES Int
      pg  = cryptoCoerce tby  :: PAGES Int
      by@(BYTES psize) = cryptoCoerce pg
  ptr <- c_createpool psize
  out <- c_mlock ptr psize
  if out < 0 then fail "mlock_fail" else do
    fptr <- newForeignPtr ptr (return ())
    addFinalizers fptr [ c_freepool ptr psize
                       , c_munlock ptr psize
                       , c_wipe ptr psize
                       ]
    return (Pool fptr pg [Block ptr by True])
  where
    addFinalizers :: ForeignCryptoPtr -> [IO ()] -> IO ()
    addFinalizers fptr = mapM_ (addForeignPtrFinalizer fptr)

-- | Creates the initial `BookKeeper` with the pool of given size.
initBookKeeper :: CryptoCoerce size (BYTES Int)
               => size
               -> IO BookKeeper
initBookKeeper size = newIORef . singleton =<< initPool size
  where singleton a = [a]

-- | Allocates the `ForeignCryptoPtr` from the already available pool
-- of secure memory. Also adds the finalizer to mark the block as free
-- in the `BookKeeper`. Returns `Nothing` if enough free memory is not
-- available in the pool.
allocSecureMem :: CryptoCoerce size (BYTES Int)
         => size
         -> BookKeeper
         -> IO (Maybe ForeignCryptoPtr)
allocSecureMem size bkpr = do
  mcptr <- atomicModifyIORef bkpr with
  case mcptr of
    Nothing -> return Nothing
    Just cptr -> fmap Just $ newForeignPtr cptr $ freeSecureMem cptr bkpr
  where
    with [] = ([],Nothing)
    with (p:ps) = case allocFromPool size p of
      (_,Nothing) -> first (p:) $ with ps
      (np,o)      -> (np:ps,o)

-- | Allocates a new pool if enough memory is not available in the
-- current set of pools. It might fail if the system doesn't allow
-- more memory locking.
allocSecureMem' :: CryptoCoerce size (BYTES Int)
                => size
                -> BookKeeper
                -> IO ForeignCryptoPtr
allocSecureMem' size bkpr =
  maybe addPool return =<< allocSecureMem size bkpr
  where
    addPool = do
      (np,Just cptr) <- allocFromPool size `fmap` initPool size
      atomicModifyIORef bkpr (\a -> (np:a,()))
      newForeignPtr cptr (freeSecureMem cptr bkpr)

-- | Marks the associated block as free. Also frees any unused pool
-- created by `unsafeAllocSecureMem`. It does not frees the initial
-- pool created by `initBookKeeper` even if the pool is unused.
freeSecureMem :: CryptoPtr
              -> BookKeeper
              -> IO ()
freeSecureMem cptr bkpr =
  maybe (return ()) finalizeForeignPtr =<< atomicModifyIORef bkpr with
  where
    with [] = ([],Nothing)
    with (p@(Pool fp s _):ps)
      | cptr >= uptr fp && cptr < movePtr (uptr fp) s = do
        let npool = freeInPool cptr p
        case (npool,ps) of
          -- Only one block which is free means pool is free
          -- ps has atleast one element means it is not the default pool
          (Pool _ _ [Block _ _ True],(_:_)) -> (ps,Just fp)
          _                                 -> (npool:ps,Nothing)
      | otherwise = first (p:) $ with ps
    uptr fp = unsafeForeignPtrToPtr fp
