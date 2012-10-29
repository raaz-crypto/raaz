{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE FlexibleContexts  #-}
module Raaz.Hash
       ( CryptoHash(..)
       , withHashCxt
       , hash
       , hashLazy
       ) where

import Control.Exception(finally)
import Control.Monad(foldM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO.Unsafe(unsafePerformIO)


import Raaz.Types(CryptoStore, CryptoPtr, toByteString)


-- | The class that captures a Hash function. The associated type
-- @Hash h@ captures the actual Hash value.
--
-- [Warning] While defining the @'Eq'@ instance of @'Hash' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
--

class ( Eq          (Hash h)
      , CryptoStore (Hash h)
      ) => CryptoHash h where

  -- | The hash value.
  data Hash h        :: *
  -- | The hash context
  type HashCxt h     :: *

  -- | The size of message blocks in bytes.
  hashBlockSize  :: h -> Int

  -- | Alloc a new context for use.
  newHashCxt     :: h -> IO (HashCxt h)

  -- | Free the resource associated with a context. Use of the context
  -- again leads to undefined behaviour.
  freeHashCxt    :: h -> HashCxt h -> IO ()

  -- | Resets the context for reuse in the next hashing.
  resetHashCxt   :: h -> HashCxt h -> IO (HashCxt h)

  -- | Add the next chunk of data.
  addHashData    :: h -> HashCxt h -> B.ByteString -> IO (HashCxt h)

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
                    -> IO (HashCxt h)

  -- | This is to compute the hash of an already computed hash. This
  -- is a common operation when constructing HMAC. There is a default
  -- definition of this function but you may provide an efficient one
  -- to improve HMAC computation.
  hashHash :: h
           -> HashCxt h
           -> Hash h
           -> IO (Hash h)
           
  hashHash h cxt hsh = addHashData h cxt (toByteString hsh)
                     >>= finaliseHash h
           
-- | Run a computation using a hash cxt
withHashCxt :: CryptoHash h
            => h
            -> (HashCxt h -> IO a)  -- ^ The action to run
            -> IO a
withHashCxt h act = do cxt <- newHashCxt h
                       act cxt `finally` freeHashCxt h cxt


-- | Compute the hash of a strict bytestring.
hash :: CryptoHash h
     => h              -- ^ The hash algorithm
     -> B.ByteString   -- ^ The data
     -> Hash h
hash h bs = unsafePerformIO  $ withHashCxt h act
  where act cxt = addHashData h cxt bs >>= finaliseHash h


-- | Compute the hash of a lazy bytestring.
hashLazy :: CryptoHash h
         => h
         -> L.ByteString
         -> Hash h
hashLazy h lbs = unsafePerformIO $ withHashCxt h act
  where act cxt = foldM (addHashData h) cxt (L.toChunks lbs)
                  >>= finaliseHash h
