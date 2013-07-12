{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}

module Raaz.Primitives.Hash
       ( HashImplementation(..)
       , Hash
       , HMAC(..)
       , sourceHash', sourceHash
       , hash', hash
       , hashFile', hashFile
       ) where

import           Control.Applicative  ((<$>))
import           Control.Monad        (foldM)
import           Data.Word            (Word64)
import           Data.Bits
import qualified Data.ByteString      as B
import           Foreign.Storable     (Storable(..))
import           Prelude              hiding (length)
import           System.IO            (withBinaryFile, IOMode(ReadMode))
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.ByteSource
import           Raaz.Primitives
import           Raaz.Primitives.MAC
import           Raaz.Types
import           Raaz.Util.ByteString (length)
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
class ( Implementation i
      , HasPadding     (PrimitiveOf i)
      , Eq             (PrimitiveOf i)
      , CryptoStore    (PrimitiveOf i)
      ) => HashImplementation i where

  -- | The context to start the hash algorithm.
  startHashCxt :: Cxt i

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt i -> PrimitiveOf i

  -- | Computes the iterated hash, useful for password
  -- hashing. Although a default implementation is given, you might
  -- want to give an optimized specialised version of this function.
  iterateHash :: i             -- ^ Implementation
              -> Int           -- ^ Number of times to iterate
              -> PrimitiveOf i -- ^ starting hash
              -> PrimitiveOf i
  iterateHash i n h = unsafePerformIO $ allocaBuffer tl (iterateN h)
      where dl = BYTES $ sizeOf h              -- length of msg
            pl = padLength h (cryptoCoerce dl) -- length of pad
            tl = dl + pl                       -- total length
            blks = cryptoCoerce tl `asTypeOf` blocksOf 1 h
            getStartCxt :: HashImplementation i => i -> PrimitiveOf i -> Cxt i
            getStartCxt _ _ = startHashCxt
            iterateN _ cptr = do
              unsafePad h bits padPtr
              foldM iterateOnce h [1..n]
              where
                bits = cryptoCoerce dl
                padPtr = cptr `movePtr` dl
                iterateOnce hsh _ = do
                  store cptr hsh
                  finaliseHash <$> process (getStartCxt i h) blks cptr


  -- | This functions processes data which itself is a hash. One can
  -- use this for iterated hash computation, hmac construction
  -- etc. There is a default definition of this function but
  -- implementations can give a more efficient version.
  processHash :: Cxt i       -- ^ Context obtained by processing so far
              -> BITS Word64 -- ^ number of bits processed so far
                             -- (exculding the bits in the hash)
              -> PrimitiveOf i
              -> PrimitiveOf i
  processHash cxt bits h = unsafePerformIO $ allocaBuffer tl go
     where sz      = BYTES $ sizeOf h
           tBits   = bits + cryptoCoerce sz
           pl      = padLength h tBits
           tl      = sz + pl
           go cptr = do
              store cptr h
              unsafePad h tBits $ cptr `movePtr` sz
              finaliseHash <$> process cxt (cryptoCoerce tl) cptr

class (CryptoPrimitive h, HashImplementation (Recommended h)) => Hash h where

-- | Hash a given byte source.
sourceHash' :: ( HashImplementation i, ByteSource src )
            => i    -- ^ Implementation
            -> src  -- ^ Message
            -> IO (PrimitiveOf i)
sourceHash' i = fmap finaliseHash . transformContext (startContext i)
   where startContext :: HashImplementation i => i -> Cxt i
         startContext _ = startHashCxt

sourceHash :: ( Hash h, ByteSource src )
           => src  -- ^ Message
           -> IO h
sourceHash src = go undefined
  where go :: Hash h => Recommended h -> IO h
        go i = sourceHash' i src

-- | Compute the Hash of Pure Byte Source. Implementation dependent.
hash' :: ( HashImplementation i, PureByteSource src )
     => i    -- ^ Implementation
     -> src  -- ^ Message
     -> PrimitiveOf i
hash' i = unsafePerformIO . sourceHash' i

-- | Compute the Hash of Pure Byte Source using recommended
-- implementation.
hash :: ( Hash h, PureByteSource src )
     => src  -- ^ Message
     -> h
hash = unsafePerformIO . sourceHash

-- | Hash a given file given `FilePath`. Implementation dependent.
hashFile' :: HashImplementation i
          => i           -- ^ Implementation
          -> FilePath    -- ^ File to be hashed
          -> IO (PrimitiveOf i)
hashFile' i fp = withBinaryFile fp ReadMode $ sourceHash' i

-- | Hash a given file given `FilePath` based on recommended
-- implementation.
hashFile :: Hash h
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fp = withBinaryFile fp ReadMode sourceHash

-- | The HMAC associated to a hash value. The `Eq`
-- instance for HMAC -- is essentially the `Eq` instance for the
-- underlying hash and hence -- is safe against timing attack
-- (provided the underlying hashs -- comparison is safe under timing
-- attack).
newtype HMAC h = HMAC h deriving (Eq, Storable,CryptoStore)

getHash :: HMAC h -> h
getHash _ = undefined

instance Primitive h => Primitive (HMAC h) where
  blockSize = blockSize . getHash

instance ( Implementation i )
           => Implementation (HMAC i) where

  type PrimitiveOf (HMAC i) = HMAC (PrimitiveOf i)

  newtype Cxt (HMAC i) = HMACCxt (Cxt i)

  process (HMACCxt cxt) blks cptr = HMACCxt <$> process cxt blks' cptr
          where blks' = toEnum $ fromEnum blks

  processSingle (HMACCxt cxt) cptr = HMACCxt <$> processSingle cxt cptr

  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . getHash

instance CryptoPrimitive p => CryptoPrimitive (HMAC p) where
  type Recommended (HMAC p) = HMAC (Recommended p)

-- The instance is a straight forward definition from the
-- corresponding hash. Recall that hmac is computed as follows
--
-- > hmac k m = hashByteString $ k2 ++ innerhash
-- >          where inner = toByteString $ hashByteString k1 m
-- >
--
-- where k1 and k2 are the inner and outer pad respectively each of 1
-- block length. The HasPadding instance of HMAC has to account for an
-- additional block of data arising out of the concatination of k1 in
-- front of the message.

instance ( Primitive h, HasPadding h )
         => HasPadding (HMAC h) where

  padLength hmac bits = padLength h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  padding hmac bits = padding h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  unsafePad hmac bits = unsafePad h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  maxAdditionalBlocks  = toEnum . fromEnum . maxAdditionalBlocks . getHash



instance HashImplementation i => MACImplementation (HMAC i) where

  -- The HMAC construction can be seen as two hashing stage
  --
  -- 1. The hash of the inner pad concatenated to the message and
  -- 2. The outer pad concatenated to the hash obtained in stage 1.
  --
  -- The inner pad and outer pad has length exactly 1 block and hence
  -- in the MACSecret datatype we keep trak of the context after hashing
  -- them.

  data MACSecret (HMAC i) = HMACSecret !(Cxt i) --  hash of the inner pad
                                       !(Cxt i) --  hash of the other pad

  startMACCxt (HMACSecret c1 _ ) = HMACCxt c1

  finaliseMAC (HMACSecret _  c2) (HMACCxt cxt) = HMAC (processHash c2 blkSize h)
    where blkSize    = cryptoCoerce $ blocksOf 1 h
          h          = finaliseHash cxt

  toMACSecret        = toHMACSecret undefined


toHMACSecret :: HashImplementation i
             => HMAC (PrimitiveOf i)
             -> B.ByteString
             -> MACSecret (HMAC i)
toHMACSecret hmac bs = go undefined hmac
  where go :: HashImplementation i
           => i
           -> HMAC (PrimitiveOf i)
           -> MACSecret (HMAC i)
        go i hmac' | length bs <= blkSize = toHMACSecret' hmac' bs
                   | otherwise            = toHMACSecret' hmac'
                                                    $ toByteString (hash' i bs)
        h       = getHash hmac
        blkSize = cryptoCoerce $ blocksOf 1 h

toHMACSecret' :: HashImplementation i
              => HMAC (PrimitiveOf i)
              -> B.ByteString
              -> MACSecret (HMAC i)
toHMACSecret' hmac bs = unsafePerformIO $ allocaBuffer oneBlock (go undefined)
  where h = getHash hmac
        cxt0 :: HashImplementation i => i -> Cxt i
        cxt0 _ = startHashCxt
        oneBlock = blocksOf 1 h
        bsPad = B.append bs $ B.replicate (len - bslen) 0
        opad  = B.map (xor 0x5c) bsPad
        ipad  = B.map (xor 0x36) bsPad
        BYTES len   = cryptoCoerce oneBlock
        BYTES bslen = length bs
        go :: HashImplementation i => i -> CryptoPtr -> IO (MACSecret (HMAC i))
        go i cptr = do _ <- fillBytes (BYTES len) ipad cptr
                       icxt <- processSingle (cxt0 i) cptr
                       _ <- fillBytes (BYTES len) opad cptr
                       ocxt <- processSingle (cxt0 i) cptr
                       return $ HMACSecret icxt ocxt
