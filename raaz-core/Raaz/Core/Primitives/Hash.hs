{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE EmptyDataDecls             #-}

module Raaz.Core.Primitives.Hash
       ( Hash(..), HashMemoryBuf
       , sourceHash', sourceHash
       , hash', hash
       , hashFile', hashFile
       ) where

import           Control.Applicative  ((<$>))
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Foreign.Storable     ( Storable )
import           Prelude              hiding (length)
import           System.IO            (withBinaryFile, IOMode(ReadMode), Handle)
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr   (byteSize)


-- | Type class capturing a cryptographic hash. The important
-- properties of a hash are
--
-- 1. There is a default starting context
--
-- 2. The hash value can be recovered from the final context
--
-- 3. There should be a padding strategy for padding non-integral
--    multiples of block size. In raaz we allow hashing only byte
--    messages even though standard hashes also allow hashing bit
--    messages.
--
class ( SafePrimitive h
      , PaddableGadget (Recommended h)
      , PaddableGadget (Reference h)
      , FinalizableMemory (MemoryOf (Recommended h))
      , FinalizableMemory (MemoryOf (Reference h))
      , FV (MemoryOf (Recommended h)) ~ Key h
      , FV (MemoryOf (Reference h)) ~ Key h
      , HasPadding h
      , CryptoPrimitive h
      , Eq h
      , EndianStore h
      ) => Hash h where
  -- | Get the intial IV for the hash.
  defaultCxt :: h -> Key h

  -- | Calculate the digest from the Context.
  hashDigest :: Key h -> h


-- | Often we want to hash some data which is itself the hash of some
-- other data. e.g. computing iterated hash of a password or hmac. We
-- define a memory buffer for such applications.
type HashMemoryBuf h = MemoryBuf (HashMemoryBufSize h)

-- | The `Bufferable` type used to define `HashMemoryBuffer`
data HashMemoryBufSize h

instance Hash h => Bufferable (HashMemoryBufSize h) where
  maxSizeOf hbsz = padLength thisHash (inBits sz) + sz
    where sz       = byteSize thisHash
          thisHash = getH hbsz
          getH     :: HashMemoryBufSize h -> h
          getH _   = undefined

-- | Hash a given byte source.
sourceHash' :: ( ByteSource src
               , Hash h
               , PaddableGadget g
               , h ~ PrimitiveOf g
               , FinalizableMemory (MemoryOf g)
               , FV (MemoryOf g) ~ Key h
               )
            => g    -- ^ Gadget
            -> src  -- ^ Message
            -> IO h
sourceHash' g src = hashDigest <$> (withGadget (defaultCxt $ primitiveOf g) $ go g)
  where go :: ( Gadget g1
              , Hash (PrimitiveOf g1)
              , PaddableGadget g1
              , FinalizableMemory (MemoryOf g1)
              )
            => g1 -> g1 -> IO (FV (MemoryOf g1))
        go _ gad =  do
          transformGadget gad src
          finalize gad
{-# INLINEABLE sourceHash' #-}

-- | Compute the hash of a byte source.
sourceHash :: ( Hash h, ByteSource src )
           => src  -- ^ Message
           -> IO h
sourceHash src = go undefined
  where go :: Hash h => Recommended h -> IO h
        go i = sourceHash' i src
{-# INLINEABLE sourceHash #-}
{-# SPECIALIZE sourceHash :: Hash h => B.ByteString -> IO h #-}
{-# SPECIALIZE sourceHash :: Hash h => L.ByteString -> IO h #-}
{-# SPECIALIZE sourceHash :: Hash h => Handle -> IO h #-}

-- | Compute the Hash of Pure Byte Source. Implementation dependent.
hash' :: ( PureByteSource src
         , Hash h
         , PaddableGadget g
         , FinalizableMemory (MemoryOf g)
         , FV (MemoryOf g) ~ Key h
         , h ~ PrimitiveOf g
         )
      => g    -- ^ Gadget
      -> src  -- ^ Message
      -> h
hash' g = unsafePerformIO . sourceHash' g
{-# INLINEABLE hash' #-}


-- | Compute the Hash of pure byte source.
hash :: ( Hash h, PureByteSource src )
     => src  -- ^ Message
     -> h
hash = unsafePerformIO . sourceHash
{-# INLINEABLE hash #-}
{-# SPECIALIZE hash :: Hash h => B.ByteString -> h #-}
{-# SPECIALIZE hash :: Hash h => L.ByteString -> h #-}

-- | Hash a given file given `FilePath`. Implementation dependent.
hashFile' :: ( Hash h
             , PaddableGadget g
             , FinalizableMemory (MemoryOf g)
             , FV (MemoryOf g) ~ Key h
             , h ~ PrimitiveOf g
             )
          => g           -- ^ Implementation
          -> FilePath    -- ^ File to be hashed
          -> IO h

hashFile' g fp = withBinaryFile fp ReadMode $ sourceHash' g
{-# INLINEABLE hashFile' #-}

-- | Compute the hash of a given file.
hashFile :: Hash h
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fp = withBinaryFile fp ReadMode sourceHash
{-# INLINEABLE hashFile #-}
