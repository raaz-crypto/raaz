{-|

Abstraction of a memory object.

-}

module Raaz.Memory
       ( -- * Memory
         Memory(..)
       ) where

-- | Any cryptographic primitives use memory to store stuff. This
-- class abstracts all types that hold some memory. Besides the usual
-- operations of allocation and freeing, cryptographic application
-- often requires securing the memory from being swapped out (think of
-- memory used to store private keys or passwords). This abstraction
-- supports memory securing. If your platform supports memory locking,
-- then securing a memory will prevent the memory from being swapped
-- to the disk. Once secured the memory location is overwritten by
-- nonsense before being freed.
--
class Memory m where

  -- | Allocate the memory.
  newMemory    :: IO m

  -- | Free the memory.
  freeMemory   :: m -> IO ()

  -- | Secures the memory by preventing it from being swapped to the
  -- permanent storage (provided the platform supports it). The return
  -- value tells whether we were able to secure the memory or not.
  secureMemory   :: m -> IO Bool

  -- | Perform an action which makes use of this memory. The memory
  -- allocated will automatically be freed when the action finishes
  -- either gracefully or with some exception. Besides being safer,
  -- this method might be more efficient as the memory might be
  -- allocated from the stack directly and will have very little GC
  -- overhead.
  withMemory   :: (m -> IO a) -> IO a

  -- | Similar to `withMemory` but allocates a secure memory for the
  -- action.
  withSecureMemory :: (m -> IO a) -> IO a
