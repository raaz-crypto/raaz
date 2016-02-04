{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE ConstraintKinds           #-}
module Raaz.Hash.Internal
       ( -- * Combinators for computing hashes
         Hash(..)
       , hash, hashFile, hashSource
         -- ** Computing hashes using non-standard implementations.
       , hash', hashFile', hashSource'
         -- * Hash implementations.
       , HashI(..), SomeHashI(..), HashM
         -- * Memory used by most hashes.
       , HashMemory(..), extractLength, updateLength
       -- * Some low level functions.
       , completeHashing
       ) where

import           Control.Applicative
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Data.Word
import           Foreign.Storable
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)

import Raaz.Core

-- | The Hash implementation. Implementations should ensure the following.
--
-- 1. The action @compress impl ptr blks@ should only read till the @blks@ offset starting
--    at ptr and never write any data.
--
-- 2. The action @padFinal impl ptr byts@ should touch at most @⌈byts/blocksize⌉ + padBlocks@ blocks
--    starting at ptr. It should not write anything till the @byts@ offset but may write stuff
--    beyond that.
--
-- An easy to remember this rule is to remember that computing hash of
-- a payload should not modify the payload.
--
data HashI h m = HashI
  { compress       :: Pointer -> BLOCKS h  -> MT m () -- ^ compress the blocks,
  , compressFinal  :: Pointer -> BYTES Int -> MT m () -- ^ pad and process the final bytes,
  }

-- | Constraints that a memory used by a hash implementation should satisfy.
type HashM h m = (Initialisable m (), Extractable m h)

data SomeHashI h = forall m . HashM h m =>
     SomeHashI (HashI h m)

-- | Type class capturing a cryptographic hash.
class ( Primitive h
      , EndianStore h
      , Encodable h
      , Eq h
      , Implementation h ~ SomeHashI h
      ) => Hash h where
  -- | Cryptographic hashes can be computed for messages that are not
  -- a multiple of the block size. This combinator computes the
  -- maximum size of padding that can be attached to a message.
  additionalPadBlocks :: h -> BLOCKS h
{--

data HashImplementation h = forall m . Memory m => HashImplementation (HashI h m)
-- | Get the implementation of a hash.
implementation :: (Hash h, Memory m) => HashI h m -> Implementation h
implementation = HashImplementation
{-# INLINE implementation #-}

--}

-- | Compute the hash of a pure byte source like, `B.ByteString`.
hash :: ( Hash h, PureByteSource src )
     => src  -- ^ Message
     -> h
hash = unsafePerformIO . hashSource
{-# INLINEABLE hash #-}
{-# SPECIALIZE hash :: Hash h => B.ByteString -> h #-}
{-# SPECIALIZE hash :: Hash h => L.ByteString -> h #-}

-- | Compute the hash of file.
hashFile :: Hash h
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fileName = withBinaryFile fileName ReadMode $ hashSource
{-# INLINEABLE hashFile #-}


-- | Compute the hash of a generic byte source.
hashSource :: ( Hash h, ByteSource src )
           => src  -- ^ Message
           -> IO h
hashSource = go undefined
  where go :: (Hash h, ByteSource src) => h -> src -> IO h
        go h = hashSource' $ recommended h

{-# INLINEABLE hashSource #-}
{-# SPECIALIZE hashSource :: Hash h => B.ByteString -> IO h #-}
{-# SPECIALIZE hashSource :: Hash h => L.ByteString -> IO h #-}
{-# SPECIALIZE hashSource :: Hash h => Handle -> IO h #-}


-- | Similar to `hash` but the user can specify the implementation to
-- use.
hash' :: ( PureByteSource src
         , Hash h
         )
      => Implementation h -- ^ Implementation
      -> src              -- ^ the message as a byte source.
      -> h
hash' imp = unsafePerformIO . hashSource' imp
{-# INLINEABLE hash' #-}


-- | Similar to hashFile' but the user can specify the implementation
-- to use.
hashFile' :: Hash h
          => Implementation h  -- ^ Implementation
          -> FilePath          -- ^ File to be hashed
          -> IO h
hashFile' imp fileName = withBinaryFile fileName ReadMode $ hashSource' imp
{-# INLINEABLE hashFile' #-}


-- | Similar to @hashSource@ but the user can specify the
-- implementation to use.
hashSource' :: (Hash h, ByteSource src)
            => Implementation h
            -> src
            -> IO h
hashSource' (SomeHashI impl) src =
  insecurely $ initialise () >> completeHashing impl src

-- | Gives a memory action that completes the hashing procedure with
-- the rest of the source. Useful to compute the hash of a source with
-- some prefix (like in the HMAC procedure).
completeHashing :: (Hash h, ByteSource src, HashM h m)
                => HashI h m
                -> src
                -> MT m h
completeHashing (HashI{..}) src =
  allocate totalSize $ \ ptr -> do
    let comp                = compress ptr bufSize
        finish bytes        = compressFinal ptr bytes >> extract
      in processChunks comp finish src bufSize ptr
  where bufSize             = atLeast l1Cache + 1
        totalSize           = bufSize + additionalPadBlocks undefined

-- | Computing hashes involves chunking the message into blocks and
-- compressing one block at a time. Usually this compression makes use
-- of the hash of the previous block and the length of the message
-- seen so far for compressing the current block. This memory element
-- helps keep track of these items.
data HashMemory h =
  HashMemory
  { hashCell          :: MemoryCell h              -- ^ Cell to store the hash
  , messageLengthCell :: MemoryCell (BITS Word64)  -- ^ Cell to store the length
  }

instance Storable h => Memory (HashMemory h) where

  memoryAlloc   = HashMemory <$> memoryAlloc <*> memoryAlloc

  underlyingPtr = underlyingPtr . hashCell

instance Storable h => Initialisable (HashMemory h) h where
  initialise h = do
    liftSubMT hashCell          $ initialise h
    liftSubMT messageLengthCell $ initialise (0 :: BITS Word64)

instance Storable h => Extractable (HashMemory h) h where
  extract = liftSubMT hashCell extract

-- | Extract the length of the message hashed so far.
extractLength :: MT (HashMemory h) (BITS Word64)
extractLength = liftSubMT messageLengthCell extract
{-# INLINE extractLength #-}


-- | Update the message length by a given amount.
updateLength :: LengthUnit u => u -> MT (HashMemory h) ()
{-# INLINE updateLength #-}
updateLength u = liftSubMT messageLengthCell $ modify ((+) nBits)
  where nBits :: BITS Word64
        nBits =  inBits u
