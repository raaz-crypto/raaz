{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash
       ( Hash
       , HMAC(..)
       , hash
       , hashByteString, hashByteString'
       , hashLazyByteString, hashLazyByteString'
       , hashFile, hashFile'
       ) where

import           Control.Applicative((<$>))
import           Control.Monad (foldM)
import           Data.Word(Word64)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Foreign.Storable(Storable(..))
import           Prelude hiding (length)
import           System.IO.Unsafe(unsafePerformIO)
import           System.IO(withBinaryFile, IOMode(..))

import           Raaz.Types
import           Raaz.Primitives
import           Raaz.ByteSource
import           Raaz.MAC
import           Raaz.Util.ByteString(length)
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
      , BlockImplementation i h
      ) => HashImplementation i h where

  -- | The context to start the hash algorithm.
  startHashCxt   :: Cxt i h

  -- | How to finalise the hash from the context.
  finaliseHash :: Cxt i h -> h

  -- | Computes the iterated hash, useful for password
  -- hashing. Although a default implementation is given, you might
  -- want to give an optimized specialised version of this function.
  iterateHash :: i      -- ^ Implementation to use
              -> Int    -- ^ Number of times to iterate
              -> h      -- ^ starting hash
              -> h
  iterateHash i n h = unsafePerformIO $ allocaBuffer tl iterateN
      where dl = BYTES $ sizeOf h              -- length of msg
            pl = padLength h (cryptoCoerce dl) -- length of pad
            tl = dl + pl                       -- total length
            blks = cryptoCoerce tl `asTypeOf` blocksOf 1 h
            iterateN cptr = do
              unsafePad h bits padPtr
              foldM iterateOnce h [1..n]
              where
                bits = cryptoCoerce dl
                padPtr = cptr `movePtr` dl
                iterateOnce hsh _ = do
                  store cptr hsh
                  finaliseHash <$> process (startHashCxt `asTypeOf` getCxt i h)
                                           blks
                                           cptr
            getCxt :: i -> h -> Cxt i h
            getCxt = undefined

  -- | This functions processes data which itself is a hash. One can
  -- use this for iterated hash computation, hmac construction
  -- etc. There is a default definition of this function but
  -- implementations can give a more efficient version.
  processHash :: Cxt i h       -- ^ Context obtained by processing so far
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

class (BlockPrimitive h, HashImplementation (DefaultBlockImplementation h) h) =>
      Hash h where

-- | Hash a given byte source.
hash' :: ( ByteSource src
         , HashImplementation i h
         )
      => i    -- ^ Implementation to use
      -> src  -- ^ Source
      -> IO h
hash' i = fmap finaliseHash . transformContext (start i undefined)
   where start :: HashImplementation i h => i -> h -> Cxt i h
         start _ _ = startHashCxt

-- | For default implementation.
hash :: ( Hash h
        , ByteSource src
        )
     => src
     -> IO h
hash = go undefined undefined
  where go :: (ByteSource src, Hash h) =>
              h -> DefaultBlockImplementation h -> src -> IO h
        go _ i = hash' i

-- | Hash a strict bytestring.
hashByteString' :: ( HashImplementation i h )
                => i            -- ^ Implementation to use
                -> B.ByteString -- ^ Source
                -> h
hashByteString' i = unsafePerformIO . hash' i

-- | For default implementation.
hashByteString :: Hash h
               => B.ByteString
               -> h
hashByteString = unsafePerformIO . hash

-- | Hash a lazy bytestring.
hashLazyByteString' :: HashImplementation i h
                    => i            -- ^ Implementation to use
                    -> L.ByteString -- ^ Source
                    -> h
hashLazyByteString' i = unsafePerformIO . hash' i

-- | For default implementation.
hashLazyByteString :: Hash h
                   => L.ByteString
                   -> h
hashLazyByteString = unsafePerformIO . hash

-- | Hash a given file given `FilePath`
hashFile' :: HashImplementation i h
          => i           -- ^ Implementation to use
          -> FilePath    -- ^ File to be hashed
          -> IO h
hashFile' i fp = withBinaryFile fp ReadMode $ hash' i

-- | Hash a given file given `FilePath`
hashFile :: Hash h
         => FilePath    -- ^ File to be hashed
         -> IO h
hashFile fp = withBinaryFile fp ReadMode hash

-- | The HMAC associated to a hash value. The `Eq` instance for HMAC
-- is essentially the `Eq` instance for the underlying hash and hence
-- is safe against timing attack (provided the underlying hashs
-- comparison is safe under timing attack).
newtype HMAC h = HMAC h deriving (Eq, Storable, CryptoStore)

getHash :: HMAC h -> h
getHash _ = undefined

instance HasBlockSize h => HasBlockSize (HMAC h) where
  blockSize = blockSize . getHash

instance BlockImplementation i h => BlockImplementation i (HMAC h) where
  recommendedBlocks i = toEnum . fromEnum . recommendedBlocks i . getHash

  newtype Cxt i (HMAC h) = HMACCxt (Cxt i h)

  process (HMACCxt cxt) blks cptr = HMACCxt <$> process cxt blks' cptr
          where blks' = toEnum $ fromEnum blks

  processSingle (HMACCxt cxt) cptr = HMACCxt <$> processSingle cxt cptr


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

instance BlockPrimitive h => BlockPrimitive (HMAC h) where
  type DefaultBlockImplementation (HMAC h) = DefaultBlockImplementation h

instance HasPadding h => HasPadding (HMAC h) where

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



instance (HashImplementation i h) => MACImplementation i (HMAC h) where

  -- The HMAC construction can be seen as two hashing stage
  --
  -- 1. The hash of the inner pad concatenated to the message and
  -- 2. The outer pad concatenated to the hash obtained in stage 1.
  --
  -- The inner pad and outer pad has length exactly 1 block and hence
  -- in the MACSecret datatype we keep trak of the context after hashing
  -- them.

  data MACSecret i (HMAC h) = HMACSecret !(Cxt i h) --  hash of the inner pad
                                         !(Cxt i h) --  hash of the other pad

  startMACCxt (HMACSecret c1 _ ) = HMACCxt c1

  finaliseMAC (HMACSecret _  c2) (HMACCxt cxt) = HMAC $ processHash c2 blkSize h
    where blkSize    = cryptoCoerce $ blocksOf 1 h
          h          = finaliseHash cxt

  toMACSecret        = toHMACSecret undefined


toHMACSecret :: HashImplementation i h
             => HMAC h
             -> B.ByteString
             -> MACSecret i (HMAC h)
toHMACSecret hmac bs = go undefined hmac
  where h       = getHash hmac
        blkSize = cryptoCoerce $ blocksOf 1 h
        go :: HashImplementation i h => i -> HMAC h -> MACSecret i (HMAC h)
        go i hm | length bs <= blkSize = toHMACSecret' hm bs
                | otherwise            = toHMACSecret' hm $ toByteString (hashByteString' i bs `asTypeOf` h')
          where h' = getHash hm

toHMACSecret' :: HashImplementation i h
              => HMAC h
              -> B.ByteString
              -> MACSecret i (HMAC h)
toHMACSecret' hmac bs = unsafePerformIO $ allocaBuffer oneBlock go
  where h     = getHash hmac
        cxt0  = startHashCxt
        oneBlock = blocksOf 1 h
        bsPad = B.append bs $ B.replicate (len - bslen) 0
        opad  = B.map (xor 0x5c) bsPad
        ipad  = B.map (xor 0x36) bsPad
        BYTES len   = cryptoCoerce oneBlock
        BYTES bslen = length bs
        go cptr = do _ <- fillBytes (BYTES len) ipad cptr
                     icxt <- processSingle cxt0 cptr
                     _ <- fillBytes (BYTES len) opad cptr
                     ocxt <- processSingle cxt0 cptr
                     return $ HMACSecret icxt ocxt
