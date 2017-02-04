{-# LANGUAGE CPP                       #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE ConstraintKinds           #-}

-- | This module exposes the low-level internal details of
-- cryptographic hashes. Do not import this module unless you want to
-- implement a new hash or give a new implementation of an existing
-- hash.
module Raaz.Hash.Internal
       ( -- * Cryptographic hashes and their implementations.
         -- $hashdoc$
         Hash(..)
       , hash, hashFile, hashSource
         -- ** Computing hashes using non-standard implementations.
       , hash', hashFile', hashSource'
         -- * Hash implementations.
       , HashI(..), SomeHashI(..), HashM
         -- ** Implementation of truncated hashes.
       , truncatedI
         -- * Memory used by most hashes.
       , HashMemory(..), extractLength, updateLength
       -- * Some low level functions.
       , completeHashing
       ) where


#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Data.Word
import           Foreign.Storable
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)

import Raaz.Core

-- $hashdoc$
--
-- Each cryptographic hash is a distinct type and are instances of a
-- the type class `Hash`. The standard idiom that we follow for hash
-- implementations are the following:
--
-- [`HashI`:] This type captures implementations of a the hash. This
-- type is parameterised over the memory element used by the
-- implementation.
--
-- [`SomeHashI`:] This type is the existentially quantified version of
-- `HashI` over its memory element. Thus it exposes only the interface
-- and not the internals of the implementation. The `Implementation`
-- associated type of a hash is the type `SomeHashI`
--
-- To support a new hash, a developer needs to:
--
-- 1. Define a new type which captures the result of hashing. This
--    type should be an instance of the class `Hash`.
--
-- 2. Define an implementation, i.e. a value of the type `SomeHashI`.
--
-- 3. Define a recommended implementation, i.e. an instance of the
--    type class `Raaz.Core.Primitives.Recommendation`

-------------------- Hash Implementations --------------------------

-- | The Hash implementation. Implementations should ensure the
-- following.
--
-- 1. The action @compress impl ptr blks@ should only read till the
-- @blks@ offset starting at ptr and never write any data.
--
-- 2. The action @padFinal impl ptr byts@ should touch at most
-- @⌈byts/blocksize⌉ + padBlocks@ blocks starting at ptr. It should
-- not write anything till the @byts@ offset but may write stuff
-- beyond that.
--
-- An easy to remember this rule is to remember that computing hash of
-- a payload should not modify the payload.
--
data HashI h m = HashI
  { hashIName           :: String
  , hashIDescription    :: String
  , compress       :: Pointer -> BLOCKS h  -> MT m ()
                      -- ^ compress the blocks,
  , compressFinal  :: Pointer -> BYTES Int -> MT m ()
                      -- ^ pad and process the final bytes,
  , compressStartAlignment :: Alignment
  }

instance BlockAlgorithm (HashI h m) where
  bufferStartAlignment = compressStartAlignment

-- | The constraints that a memory used by a hash implementation
-- should satisfy.
type HashM h m = (Initialisable m (), Extractable m h, Primitive h)

-- | Some implementation of a given hash. The existentially
-- quantification allows us freedom to choose the best memory type
-- suitable for each implementations.
data SomeHashI h = forall m . HashM h m =>
     SomeHashI (HashI h m)

instance Describable (HashI h m) where
  name        = hashIName
  description = hashIDescription


instance Describable (SomeHashI h) where
  name         (SomeHashI hI) = name hI
  description  (SomeHashI hI) = description hI

instance BlockAlgorithm (SomeHashI h) where
  bufferStartAlignment (SomeHashI imp) = bufferStartAlignment imp

-- | Certain hashes are essentially bit-truncated versions of other
-- hashes. For example, SHA224 is obtained from SHA256 by dropping the
-- last 32-bits. This combinator can be used build an implementation
-- of truncated hash from the implementation of its parent hash.
truncatedI :: (BLOCKS htrunc -> BLOCKS h)
           -> (mtrunc        -> m)
           -> HashI h m -> HashI htrunc mtrunc
truncatedI coerce unMtrunc (HashI{..})
  = HashI { hashIName        = hashIName
          , hashIDescription = hashIDescription
          , compress         = comp
          , compressFinal    = compF
          , compressStartAlignment = compressStartAlignment
          }
  where comp  ptr = onSubMemory unMtrunc . compress ptr . coerce
        compF ptr = onSubMemory unMtrunc . compressFinal ptr

---------------------- The Hash class ---------------------------------

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

---------------------- Helper combinators --------------------------

-- | Compute the hash of a pure byte source like, `B.ByteString`.
hash :: ( Hash h, Recommendation h, PureByteSource src )
     => src  -- ^ Message
     -> h
hash = unsafePerformIO . hashSource
{-# INLINEABLE hash #-}
{-# SPECIALIZE hash :: (Hash h, Recommendation h) => B.ByteString -> h #-}
{-# SPECIALIZE hash :: (Hash h, Recommendation h) => L.ByteString -> h #-}

-- | Compute the hash of file.
hashFile :: ( Hash h, Recommendation h)
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fileName = withBinaryFile fileName ReadMode hashSource
{-# INLINEABLE hashFile #-}


-- | Compute the hash of a generic byte source.
hashSource :: ( Hash h, Recommendation h, ByteSource src )
           => src  -- ^ Message
           -> IO h
hashSource = go undefined
  where go :: (Hash h, Recommendation h, ByteSource src) => h -> src -> IO h
        go h = hashSource' $ recommended h

{-# INLINEABLE hashSource #-}
{-# SPECIALIZE hashSource :: (Hash h, Recommendation h) => Handle -> IO h #-}


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

-- TODO: For bytestrings (strict and lazy) we can do better. We can
-- avoid copying as the bytestring exposes the underlying
-- pointer. However, there is a huge cost if the underlying pointer
-- does not start at the machine alignment boundary. The idea
-- therefore is to process strict bytestring is multiples of blocks
-- directly if the starting pointer is aligned.
--
-- More details in the bug report #256.
--
-- https://github.com/raaz-crypto/raaz/issues/256
--

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
completeHashing imp@(HashI{..}) src =
  allocate $ \ ptr -> let
    comp                = compress ptr bufSize
    finish bytes        = compressFinal ptr bytes >> extract
    in processChunks comp finish src bufSize ptr
  where bufSize             = atLeast l1Cache + 1
        totalSize           = bufSize + additionalPadBlocks undefined
        allocate            = liftPointerAction $ allocBufferFor (SomeHashI imp) totalSize

----------------------- Hash memory ----------------------------------

-- | Computing cryptographic hashes usually involves chunking the
-- message into blocks and compressing one block at a time. Usually
-- this compression makes use of the hash of the previous block and
-- the length of the message seen so far to compressing the current
-- block. Most implementations therefore need to keep track of only
-- hash and the length of the message seen so. This memory can be used
-- in such situations.
data HashMemory h =
  HashMemory
  { hashCell          :: MemoryCell h
                         -- ^ Cell to store the hash
  , messageLengthCell :: MemoryCell (BITS Word64)
                         -- ^ Cell to store the length
  }

instance Storable h => Memory (HashMemory h) where

  memoryAlloc     = HashMemory <$> memoryAlloc <*> memoryAlloc

  unsafeToPointer = unsafeToPointer . hashCell

instance Storable h => Initialisable (HashMemory h) h where
  initialise h = do
    onSubMemory hashCell          $ initialise h
    onSubMemory messageLengthCell $ initialise (0 :: BITS Word64)

instance Storable h => Extractable (HashMemory h) h where
  extract = onSubMemory hashCell extract

-- | Extract the length of the message hashed so far.
extractLength :: MT (HashMemory h) (BITS Word64)
extractLength = onSubMemory messageLengthCell extract
{-# INLINE extractLength #-}


-- | Update the message length by a given amount.
updateLength :: LengthUnit u => u -> MT (HashMemory h) ()
{-# INLINE updateLength #-}
updateLength u = onSubMemory messageLengthCell $ modify (nBits +)
  where nBits :: BITS Word64
        nBits =  inBits u
