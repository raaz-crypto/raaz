{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.Hash
       ( Hash(..)
       , hash
       , hashByteString
       , hashLazyByteString
       , hashFile
       ) where

import           Control.Applicative((<$>))
import           Control.Monad (foldM)
import           Data.Word(Word64)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Foreign.Storable(Storable(..))
import           System.IO.Unsafe(unsafePerformIO)

import           Raaz.Types
import           Raaz.Primitives
import           Raaz.ByteSource
import           Raaz.Util.Ptr

-- | The class abstracts an arbitrary hash type. A hash should be a
-- block primitive. Computing the hash involved starting at a fixed
-- context and iterating through the blocks of data (suitably padded)
-- by the process function. The last context is then finalised to the
-- value of the hash.
--
-- A Minimum complete definition include @`startHashCxt`@,
-- @`finaliseHash`@, However, for efficiency you might want to define
-- all of the members separately.
--
-- [Warning:] While defining the @'Eq'@ instance of @'Hash' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular,
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
class ( HasPadding h
      , Eq          h
      , Storable    h
      , CryptoStore h
      ) => Hash h where

  -- | The context to start the hash algorithm.
  startHashCxt   :: h -> Cxt h

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt h -> h

  -- | Computes the iterated hash, useful for password
  -- hashing. Although a default implementation is given, you might
  -- want to give an optimized specialised version of this function.
  iterateHash :: Int    -- ^ Number of times to iterate
              -> h      -- ^ starting hash
              -> h
  iterateHash n h = unsafePerformIO $ allocaBuffer tl iterateN
      where dl = BYTES $ sizeOf h              -- length of msg
            pl = padLength h (cryptoCoerce dl) -- length of pad
            tl = dl + pl                       -- total length
            blks = cryptoCoerce tl             -- number of blocks
            iterateN cptr = do
              unsafePad h bits padPtr
              foldM iterateOnce h [1..n]
              where
                bits = cryptoCoerce dl
                padPtr = cptr `movePtr` dl
                iterateOnce h' _ = do
                  store cptr h'
                  finaliseHash <$> process (startHashCxt h') blks cptr

  -- | This functions processes data which itself is a hash. One can
  -- use this for iterated hash computation, hmac construction
  -- etc. There is a default definition of this function but
  -- implementations can give a more efficient version.
  processHash :: Cxt h       -- ^ Context obtained by processing so far
              -> BITS Word64 -- ^ number of bits processed so far
                             -- (exculding the bits in the hash)
              -> h
              -> h
  processHash cxt bits h = unsafePerformIO $ allocaBuffer tl go
     where sz      = BYTES $ sizeOf h
           tBits   = bits + cryptoCoerce sz
           pl      = padLength h tBits
           tl      = sz + pl
           go cptr = do
              store cptr h
              unsafePad h tBits $ cptr `movePtr` sz
              finaliseHash <$> process cxt (cryptoCoerce tl) cptr



-- | Hash a given byte source.
hash :: ( Hash h, ByteSource src) => src -> IO h
hash = fmap finaliseHash . transformContext (startHashCxt undefined)

-- | Hash a strict bytestring.
hashByteString :: Hash h => B.ByteString -> h
hashByteString = unsafePerformIO . hash

-- | Hash a lazy bytestring.
hashLazyByteString :: Hash h => L.ByteString -> h
hashLazyByteString = unsafePerformIO . hash

-- | Hash a given file given `FilePath`
hashFile :: Hash h
         => FilePath    -- ^ File to be hashed
         -> IO h
hashFile = fmap finaliseHash . transformContextFile (startHashCxt undefined)
