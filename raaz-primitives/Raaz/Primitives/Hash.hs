{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.Primitives.Hash
       ( Hash(..), HashImplementation(..)
       , hashByteString
       , hashLazyByteString
       ) where

import           Control.Applicative((<$>))
import           Data.Word(Word64)
import qualified Data.ByteString as B
import           Data.ByteString.Internal(unsafeCreate)
import qualified Data.ByteString.Lazy as L
import           Foreign.Ptr(castPtr)
import           Foreign.Storable(Storable(..))
import           System.IO.Unsafe

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
  -- performance of your program. Default setting is @1@.
  recommendedBlocks   :: h -> BLOCKS h
  recommendedBlocks _ = 1


-- | Underlying a cryptographic hash, whether it is one of the
-- Merkel-Damgård hashes like SHA1 or HAIFA hashes like BLAKE, is a
-- compressor which works on a fixed block of bits. This compressor is
-- what does all the hardwork and the security of the hash depends on
-- the security of this function. We capture this compressor via the
-- type class HashImplementation.

class Hash h => HashImplementation i h where
  -- | Hash functions proceeds in rounds where each round processes
  -- one block. This assocaited type captures the intermediate value
  -- required in the processing of the next block. For Merkel-Damgård
  -- this is usually just h, although one could use a more efficient
  -- representation of it. In HAIFA hashes, it usually contains the
  -- salt and the number of bits processed as well.
  data Cxt i h :: *

  -- | The context to start the hash algorithm.
  startCxt     :: i -> h -> Cxt i h

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt i h -> h

  -- | The compression function assocated with the hash.
  compress :: Cxt i h       -- ^ The context from the previous round
           -> BLOCKS h      -- ^ The number of blocks of data.
           -> CryptoPtr     -- ^ The message buffer
           -> IO (Cxt i h)

  -- | This functions is to facilitate the hmac construction. There is
  -- a default definition of this function but implementations can
  -- give a more efficient version.
  hmacOuter :: Cxt i h
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
hashByteString :: ( Hash h
                  , HashImplementation i h
                  )
               => i             -- ^ The implementation
               -> B.ByteString  -- ^ The data to hash
               -> h             -- ^ The hash

hashByteString i bs = unsafePerformIO $ compressChunks (startCxt i undefined) [bs]

-- | Hash a given lazy bytestring.
hashLazyByteString :: ( Hash h
                      , HashImplementation i h
                      )
                   => i            -- ^ The implementation
                   -> L.ByteString -- ^ The bytestring
                   -> h
hashLazyByteString i = unsafePerformIO
                     . compressChunks (startCxt i undefined)
                     . L.toChunks

-- | Compress a list of strict byte string chunks.
compressChunks :: HashImplementation i h
               => Cxt i h
               -> [B.ByteString]
               -> IO h
compressChunks cxt bs = fmap finaliseHash $ allocaBuffer bufSize $ go cxt bs 0
     where getHash  :: Cxt i h -> h
           getHash _ = undefined
           h         = getHash cxt
           nBlocks   = recommendedBlocks h
           sz        = cryptoCoerce nBlocks
           bufSize   = maxAdditionalBlocks h + nBlocks
           go context bstr bits cptr = do
                      fill <- fillUpChunks sz cptr bstr
                      either goLeft goRight fill
             where goRight rest = do
                     context' <- compress context nBlocks cptr
                     go context' rest (bits + cryptoCoerce nBlocks) cptr

                   goLeft r = do unsafePad h totalBits padPtr
                                 compress context blks cptr
                     where bufLen    = sz - r
                           pl        = padLength h totalBits
                           blks      = cryptoCoerce (bufLen + pl)
                           totalBits = bits + cryptoCoerce bufLen
                           padPtr    = cptr `movePtr` bufLen
