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

-- | The class abstracts an arbitrary hash type. Minimum complete
-- definition include @padLength@, one of @`padding`@ or @`unsafePad`@
-- and @`maxAdditionalBlocks`@. However, for efficiency you might want
-- to define all of the members separately.
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

  -- | Hash functions proceeds in rounds where each round processes
  -- one block. This assocaited type captures the intermediate value
  -- required in the processing of the next block. For Merkel-Damgård
  -- this is usually just h, although one could use a more efficient
  -- representation of it. In HAIFA hashes, it usually contains the
  -- salt and the number of bits processed as well.
  data Cxt h :: *

  -- | The context to start the hash algorithm.
  startCxt   :: h -> Cxt h

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt h -> h

  -- | Underlying a cryptographic hash, whether it is one of the
  -- Merkel-Damgård hashes like SHA1 or HAIFA hashes like BLAKE, is a
  -- compressor which works on a fixed block of bits. This compressor
  -- is what does all the hardwork and the security of the hash
  -- depends on the security of this function. The compression
  -- function assocated with the hash. This already has a default
  -- implementation in terms of compressSingle, but you can provide a
  -- more efficient implementation.
  compress :: Cxt h         -- ^ The context from the previous round
           -> BLOCKS h      -- ^ The number of blocks of data.
           -> CryptoPtr     -- ^ The message buffer
           -> IO (Cxt h)
  compress cxt b cptr = fst <$> foldM moveAndHash (cxt,cptr) [1..b]
    where
      moveAndHash (cxt',ptr) _ = do newcxt <- compressSingle cxt' ptr
                                    let moveBy = blockSize (getHash cxt)
                                    return (newcxt,movePtr ptr moveBy)
      getHash :: Cxt h -> h
      getHash _ = undefined

  -- | Reads one block from the CryptoPtr and produces the next
  -- context from the previous context. It has a default
  -- implementation in terms of compress. So you need to provide
  -- implementation of atleast one of compress or compressSingle.
  compressSingle :: Cxt h         -- ^ The context
                 -> CryptoPtr     -- ^ The message buffer
                 -> IO (Cxt h)
  compressSingle cxt cptr = compress cxt 1 cptr

  -- | There are two reasons to pad the data to be hashed. The obvious
  -- reason is to handle messages that are not multiples of the block
  -- size. Howerver, there is a more subtle reason. For hashing
  -- schemes like Merkel-Damgård, the strength of the hash crucially
  -- depends on the padding. This combinator returns the length of the
  -- padding that is to be added to the message.
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

  -- | The recommended number of blocks to hash at a time. While
  -- hashing files, bytestrings it makes sense to hash multiple blocks
  -- at a time. Setting this member appropriately (typically depends
  -- on the cache size of your machine) can drastically improve cache
  -- performance of your program. Default setting is the number of
  -- blocks that fit in @32KB@.
  recommendedBlocks   :: h -> BLOCKS h
  recommendedBlocks _ = cryptoCoerce (1024 * 32 :: BYTES Int)

  -- | Computes the iterated hash useful for password
  -- hashing. Although a default implementation is given, you might
  -- want to give an optimized specialised version of this function.
  iterateHash :: Int    -- ^ Number of times to iterate
              -> h      -- ^ starting hash
              -> h

  -- | This functions is to facilitate the hmac construction. There is
  -- a default definition of this function but implementations can
  -- give a more efficient version.
  hmacOuter :: Cxt h
            -> h
            -> h
  hmacOuter cxt h = unsafePerformIO $ allocaBuffer tl go
     where sz   :: BYTES Int   -- size of message
           pl   :: BYTES Int   -- size of padding
           bits :: BITS Word64 -- total Message size
           tl   :: BYTES Int   -- total buffer size
           sz      = BYTES $ sizeOf h
           bits    = cryptoCoerce $ blocksOf 1 h -- outer pad
                   + cryptoCoerce sz
           pl      = padLength h bits
           tl      = sz + pl
           go cptr = do
              store cptr h
              unsafePad h bits $ cptr `movePtr` sz
              finaliseHash <$> compress cxt (cryptoCoerce tl) cptr



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
                         then do context' <- compress context nBlocks cptr
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
                     context' <- compress context nBlocks cptr
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
                                    >> compress cxt blks cptr
       where totalBits = bits + cryptoCoerce bufLen
             blks      = cryptoCoerce (bufLen + padLength h totalBits)
             padPtr    = cptr `movePtr` bufLen
