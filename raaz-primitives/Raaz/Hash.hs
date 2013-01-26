{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.Hash
       ( Hash(..)
       , hashByteString
       , hashLazyByteString
       , hashFile
       , hashFileHandle
       ) where

import           Control.Applicative((<$>))
import           Control.Monad (foldM)
import           Data.Word(Word64)
import qualified Data.ByteString as B
import           Data.ByteString.Internal(unsafeCreate)
import qualified Data.ByteString.Lazy as L
import           Foreign.Ptr(castPtr)
import           Foreign.Storable(Storable(..))
import           System.IO.Unsafe
import           System.IO

import           Raaz.Types
import           Raaz.Primitives
import           Raaz.Util.ByteString
import           Raaz.Util.Ptr

-- | The class abstracts an arbitrary hash type. A hash should be a
-- block primitive. Computing the hash involved starting at a fixed
-- context and iterating through the blocks of data (suitably padded)
-- by the process function. The last context is then finalised to the
-- value of the hash.
--
-- The data to be hashed should be padded. The obvious reason is to
-- handle messages that are not multiples of the block size. Howerver,
-- there is a more subtle reason. For hashing schemes like
-- Merkel-Damgård, the strength of the hash crucially depends on the
-- padding.
--
-- A Minimum complete definition include @`startCxt`@,
-- @`finaliseHash`@, @`padLength`@, one of @`padding`@ or
-- @`unsafePad`@ and @`maxAdditionalBlocks`@. However, for efficiency
-- you might want to define all of the members separately.
--
-- [Warning:] While defining the @'Eq'@ instance of @'Hash' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular,
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
class ( BlockPrimitive h
      , Eq          h
      , Storable    h
      , CryptoStore h
      ) => Hash h where

  -- | The context to start the hash algorithm.
  startCxt   :: h -> Cxt h

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt h -> h

  -- This combinator returns the length of the padding that is to be
  -- added to the message.
  padLength :: h           -- ^ The hash type
            -> BITS Word64 -- ^ the total message size in bits.
            -> BYTES Int

  -- | This function returns the actual bytestring to pad the message
  -- with. There is a default definition of this message in terms of
  -- the unsafePad function. However, implementations might want to
  -- give a more efficient definition.
  padding   :: h -> BITS Word64 -> B.ByteString
  padding h bits = unsafeCreate len padIt
        where BYTES len = padLength h bits
              padIt     = unsafePad h bits . castPtr

  -- | This is the unsafe version of the padding function. It is
  -- unsafe in the sense that the call @unsafePad h bits cptr@ assumes
  -- that there is enough free space to put the padding string at the
  -- given pointer.
  unsafePad :: h -> BITS Word64 -> CryptoPtr -> IO ()
  unsafePad h bits = unsafeCopyToCryptoPtr $ padding h bits

  -- | This counts the number of additional blocks required so that
  -- one can hold the padding. This function is useful if you want to
  -- know the size to be allocated for your message buffers.
  maxAdditionalBlocks :: h -> BLOCKS h


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
                  finaliseHash <$> process (startCxt h') blks cptr

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



-- | Hash a given strict bytestring.
hashByteString :: Hash h
               => B.ByteString  -- ^ The data to hash
               -> h             -- ^ The hash

hashByteString bs = unsafePerformIO $ compressChunks (startCxt undefined) [bs]


-- | Hash a given lazy bytestring.
hashLazyByteString :: Hash h
                   => L.ByteString -- ^ The bytestring
                   -> h
hashLazyByteString = unsafePerformIO
                   . compressChunks (startCxt undefined)
                   . L.toChunks

-- | Hash a given file given `FilePath`
hashFile :: Hash h
         => FilePath    -- ^ File to be hashed
         -> IO h
hashFile fpth = withFile fpth ReadMode hashFileHandle

-- | Hash a given file given the file `Handle`.  It is supposed to be
-- faster than reading a file and then hashing it.
hashFileHandle :: Hash h
               => Handle      -- ^ File to be hashed
               -> IO h
hashFileHandle hndl = fmap finaliseHash $ allocaBuffer bufSize $ go cxt 0
     where getHash  :: Cxt h -> h
           getHash _ = undefined
           cxt       = startCxt undefined
           h         = getHash cxt
           nBlocks   = recommendedBlocks h
           sz        = cryptoCoerce nBlocks
           bufSize   = maxAdditionalBlocks h + nBlocks
           go context bits cptr = do
                      count <- hFillBuf hndl cptr nBlocks
                      if count == sz
                         then do context' <- process context nBlocks cptr
                                 go context' (bits + cryptoCoerce nBlocks) cptr
                         else compressLast h context bits count cptr

-- | Compress a list of strict byte string chunks.
compressChunks :: Hash h
               => Cxt h
               -> [B.ByteString]
               -> IO h
compressChunks cxt bs = fmap finaliseHash $ allocaBuffer bufSize $ go cxt bs 0
     where getHash  :: Cxt h -> h
           getHash _ = undefined
           h         = getHash cxt
           nBlocks   = recommendedBlocks h
           bufSize   = maxAdditionalBlocks h + nBlocks
           go context bstr bits cptr =   fillUpChunks bstr nBlocks cptr
                                     >>= either goLeft goRight
             where goRight rest = do
                     context' <- process context nBlocks cptr
                     go context' rest (bits + cryptoCoerce nBlocks) cptr

                   goLeft r = compressLast h context bits bufLen cptr
                        where bufLen = cryptoCoerce nBlocks - r

-- | Compressing the last bytes.
compressLast :: Hash h
             => h
             -> Cxt h
             -> BITS Word64
             -> BYTES Int   -- ^ Bytes in the buffer.
             -> CryptoPtr
             -> IO (Cxt h)
compressLast h cxt bits bufLen cptr =  unsafePad h totalBits padPtr
                                    >> process cxt blks cptr
       where totalBits = bits + cryptoCoerce bufLen
             blks      = cryptoCoerce (bufLen + padLength h totalBits)
             padPtr    = cptr `movePtr` bufLen
