{-|

A cryptographic hash function abstraction.

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}

module Raaz.Primitives.Hash
       ( Hash
       -- , HMAC(..)
       , sourceHash', sourceHash
       , hash', hash
       , hashFile', hashFile
       ) where

import           Control.Applicative  ((<$>))
import           Control.Monad        (foldM)
import           Data.Default
import           Data.Word            (Word64)
import           Data.Bits
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Foreign.Storable     (Storable(..))
import           Foreign.ForeignPtr.Safe
import           Prelude              hiding (length)
import           System.IO            (withBinaryFile, IOMode(ReadMode), Handle)
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.ByteSource
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Types
import           Raaz.Util.ByteString (length)
import           Raaz.Util.Ptr
import           Raaz.Util.SecureMemory


-- | Gadgets that compute a cryptographic hash.
class ( SafeGadget g
      , Eq          (PrimitiveOf g)
      , HasPadding  (PrimitiveOf g)
      , Default     (IV (PrimitiveOf g))
      , CryptoStore (PrimitiveOf g)
      ) => HashGadget g where

  -- | Computes the iterated hash, useful for password
  -- hashing. Although a default implementation is given, you might
  -- want to give an optimized specialised version of this function.
  iterateHash :: g             -- ^ The gadget
              -> Int           -- ^ Number of times to iterate
              -> PrimitiveOf g -- ^ starting hash
              -> IO (PrimitiveOf g)
  iterateHash g n h = allocaBuffer tl (iterateN h)
      where dl = BYTES $ sizeOf h              -- length of msg
            pl = padLength h (cryptoCoerce dl) -- length of pad
            tl = dl + pl                       -- total length
            blks = cryptoCoerce tl `asTypeOf` blocksOf 1 h
            iterateN _ cptr = do
              unsafePad h bits padPtr
              foldM iterateOnce h [1..n]
              where
                bits   = cryptoCoerce dl
                padPtr = cptr `movePtr` dl
                iterateOnce hsh _ = do
                  store cptr hsh
                  initialize g def
                  apply g blks cptr
                  finalize g

  -- | This functions processes data which itself is a hash. One can
  -- use this for iterated hash computation, hmac construction
  -- etc. There is a default definition of this function but
  -- implementations can give a more efficient version.
  processHash :: g           -- ^ The gadget
              -> BITS Word64 -- ^ number of bits processed so far
                             -- (exculding the bits in the hash)
              -> PrimitiveOf g
              -> IO (PrimitiveOf g)
  processHash g bits h = allocaBuffer tl go
     where sz      = BYTES $ sizeOf h
           tBits   = bits + cryptoCoerce sz
           pl      = padLength h tBits
           tl      = sz + pl
           go cptr = do
              store cptr h
              unsafePad h tBits $ cptr `movePtr` sz
              apply g (cryptoCoerce tl) cptr
              finalize g


class (CryptoPrimitive h, HashGadget (Recommended h)) => Hash h where

-- | Hash a given byte source.
sourceHash' :: ( HashGadget g, ByteSource src )
            => g    -- ^ Gadget
            -> src  -- ^ Message
            -> IO (PrimitiveOf g)
sourceHash' g src = do
  gad <- initializeHash g
  transformGadget gad src
  finalize gad
   where initializeHash :: HashGadget g => g -> IO g
         initializeHash _ = do
           g' <- newGadget =<< newMemory
           initialize g' def
           return g'
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
hash' :: ( HashGadget g, PureByteSource src )
     => g    -- ^ Gadget
     -> src  -- ^ Message
     -> PrimitiveOf g
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
hashFile' :: HashGadget g
          => g           -- ^ Implementation
          -> FilePath    -- ^ File to be hashed
          -> IO (PrimitiveOf g)
hashFile' g fp = withBinaryFile fp ReadMode $ sourceHash' g
{-# INLINEABLE hashFile' #-}

-- | Compute the hash of a given file.
hashFile :: Hash h
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fp = withBinaryFile fp ReadMode sourceHash
{-# INLINEABLE hashFile #-}

{-
-- | The HMAC associated to a hash value. The `Eq` instance for HMAC
-- is essentially the `Eq` instance for the underlying hash and hence
-- is safe against timing attack (provided the underlying hashs --
-- comparison is safe under timing attack).
newtype HMAC h = HMAC h deriving (Eq, Storable, CryptoStore)

-- | A function that is often used to keep type checker happy.
getHash :: HMAC h -> h
getHash _ = undefined

instance Primitive h => Primitive (HMAC h) where
  blockSize = blockSize . getHash
  -- | Stores inner and outer pad
  newtype IV (HMAC h) = HMACSecret B.ByteString

newtype HMACBuffer p = HMACBuffer ForeignCryptoPtr deriving Eq

data Gadget g => HMACGadget g =
  HMACGadget g (HMACBuffer (PrimitiveOf g))



instance (Primitive p, CryptoStore p) => Memory (HMACBuffer p) where
  newMemory = allocMem undefined
    where
      allocMem :: (Primitive p, CryptoStore p) => p -> IO (HMACBuffer p)
      allocMem p = let BYTES len = cryptoCoerce $ size p
                   in fmap HMACBuffer $ mallocForeignPtrBytes len
      size :: (Primitive p, CryptoStore p) => p -> BLOCKS p
      size p = blocksOf 1 p + cryptoCoerce (BYTES $ sizeOf p)

  freeMemory (HMACBuffer fptr) = finalizeForeignPtr fptr
  withSecureMemory f bk = allocSec undefined bk >>= f
   where
     -- Assuming Blocks are always word aligned
     size :: (Primitive p, CryptoStore p) => p -> BLOCKS p
     size p = blocksOf 1 p + cryptoCoerce (BYTES $ sizeOf p)
     allocSec :: (Primitive p, CryptoStore p)
              => p
              -> BookKeeper
              -> IO (HMACBuffer p)
     allocSec p = fmap HMACBuffer . allocSecureMem'
                    (cryptoCoerce (size p) :: BYTES Int)

instance HashGadget g => Gadget (HMACGadget g) where

  type PrimitiveOf (HMACGadget g) = HMAC (PrimitiveOf g)

  type MemoryOf (HMACGadget g) = (MemoryOf g, HMACBuffer (PrimitiveOf g))

  newGadget (gmem,hbuff) = do
    g <- newGadget gmem
    return $ HMACGadget g hbuff

  initialize (HMACGadget g hbuff) (HMACSecret bs)  = do
    initialize g def
    initHMAC (HMACGadget g hbuff) bs

  finalize (HMACGadget g (HMACBuffer fcptr)) = do
    fv <- finalize g
    withForeignPtr fcptr (flip store fv . flip movePtr (oneBlock g))
    withForeignPtr fcptr (unsafePad (getPrim g) mlen)
    initialize g def
    withForeignPtr fcptr (apply g (2 * oneBlock g))
    HMAC <$> finalize g
    where
      mlen = cryptoCoerce $ BYTES $ sizeOf (getPrim g) + len
      getPrim :: Gadget g => g -> PrimitiveOf g
      getPrim _ = undefined
      oneBlock :: Gadget g => g -> BLOCKS (PrimitiveOf g)
      oneBlock g' = blocksOf 1 (getPrim g')
      BYTES len   = cryptoCoerce $ oneBlock g

  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . getHash'
    where getHash' :: Gadget g => HMACGadget g -> g
          getHash' (HMACGadget g _) = g

  apply (HMACGadget g _) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks

instance (HashGadget g) => SafeGadget (HMACGadget g)

-- instance (CryptoPrimitive p, PrimitiveOf (HMACGadget (Recommended p)) ~ HMAC p)
--          => CryptoPrimitive (HMAC p) where
--   type Recommended (HMAC p) = HMACGadget (Recommended p)
--   type Reference   (HMAC p) = HMACGadget (Reference p)

-- The instance is a straight forward definition from the
-- corresponding hash. Recall that hmac is computed as follows
--
-- > hmac k m = hashByteString $ k2 ++ innerhash
-- >          where inner = toByteString $ hashByteString (k1 ++ m)
-- >
--
-- where k1 and k2 are the inner and outer pad respectively each of 1
-- block length. The HasPadding instance of HMAC has to account for an
-- additional block of data arising out of the concatination of k1 in
-- front of the message.

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

initHMAC :: HashGadget g
         => HMACGadget g
         -> B.ByteString
         -> IO ()
initHMAC hmacg@(HMACGadget g _) bs = go hmacg
  where
    go :: HashGadget g => HMACGadget g -> IO ()
    go (HMACGadget g' _)
      | length bs <= blkSize = initHMAC' hmacg bs
      | otherwise            = initHMAC' hmacg $ toByteString
                                               $ hash' g' bs
    getPrim :: Gadget g => g -> PrimitiveOf g
    getPrim _ = undefined
    blkSize = cryptoCoerce $ blocksOf 1 (getPrim g)

initHMAC' :: HashGadget g
          => HMACGadget g
          -> B.ByteString
          -> IO ()
initHMAC' (HMACGadget g (HMACBuffer fptr)) bs = do
  _ <- withForeignPtr fptr $ fillBytes (BYTES len) ipad
  withForeignPtr fptr $ apply g (oneBlock g)
  _ <- withForeignPtr fptr $ fillBytes (BYTES len) opad
  return ()
  where
    oneBlock :: Gadget g => g -> BLOCKS (PrimitiveOf g)
    oneBlock _ = blocksOf 1 undefined
    bsPad = B.append bs $ B.replicate (len - bslen) 0
    opad  = B.map (xor 0x5c) bsPad
    ipad  = B.map (xor 0x36) bsPad
    BYTES len   = cryptoCoerce $ oneBlock g
    BYTES bslen = length bs
-}
