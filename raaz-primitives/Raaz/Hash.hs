{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE FlexibleContexts  #-}
module Raaz.Hash
       ( CryptoHash(..)
       ) where

import Control.Exception(finally)
import qualified Data.ByteString as B
import System.IO.Unsafe(unsafePerformIO)


import Raaz.Types


-- | The class that captures a Hash function. The associated type
-- @Hash h@ captures the actual Hash value.
--
-- For potential implementers of hash we have some remarks:
--
-- WARNING: Care must be taken in defining the @'Eq'@ instance for
-- @'Hash' h@ to avoid timing based side-channel attacks. Make sure
-- that the equality operator @==@ takes time independent of the
-- input. In particular /do not/ use the deriving clause at all.
--

class ( Eq          (Hash h)
      , CryptoStore (Hash h)
      ) => CryptoHash h where

  data Hash h        :: * -- ^ The hash value.
  type HashCxt h     :: * -- ^ The hash context

  blockSize  :: h -> Int  -- ^ size of message block in bytes

  -- | Alloc a new context for use.
  newHashCxt     :: h -> IO (HashCxt h)

  -- | Free the resource associated with a context. Use of the context
  -- again leads to undefined behaviour.
  freeHashCxt    :: h -> HashCxt h -> IO ()

  -- | Resets the context for reuse in the next hashing.
  resetHashCxt   :: h -> HashCxt h -> IO ()

  -- | Add the next chunk of data.
  addHashData    :: h -> HashCxt h -> B.ByteString -> IO ()

  -- | Finalise the context to a hash value.
  finaliseHash   :: h -> HashCxt h -> IO (Hash h)

  -- | For data that is of size, which is a multiple of the block size
  -- of the hash, you can use this potentially faster method of
  -- updating the context. This method is guranteed to generate the
  -- correct output only when the number of bytes processed in the
  -- context so far is also a multiple of the block size.
  unsafeAddHashData :: h
                    -> HashCxt h -- ^ The hash context
                    -> CryptoPtr -- ^ The pointer to the first element
                    -> Int       -- ^ Number of hash blocks (not the
                                 -- number of bytes).
                    -> IO ()


-- | Run a computation using a hash cxt
withHashCxt :: CryptoHash h
            => h
            -> (HashCxt h -> IO a)  -- ^ The action to run
            -> IO a
withHashCxt h act = do cxt <- newHashCxt h
                       act cxt `finally` freeHashCxt h cxt

