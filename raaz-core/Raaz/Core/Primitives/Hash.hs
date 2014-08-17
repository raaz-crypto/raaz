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
      , FV (MemoryOf (Recommended h)) ~ Cxt h
      , FV (MemoryOf (Reference h)) ~ Cxt h
      , HasPadding h
      , CryptoPrimitive h
      , Eq h
      , EndianStore h
      ) => Hash h where
  -- | Get the intial IV for the hash.
  defaultCxt :: h -> Cxt h

  -- | Calculate the digest from the Context.
  hashDigest :: Cxt h -> h


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
               , FV (MemoryOf g) ~ Cxt h
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
         , FV (MemoryOf g) ~ Cxt h
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
             , FV (MemoryOf g) ~ Cxt h
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

{-
-- | The HMAC associated to a hash value. The `Eq` instance for HMAC
-- is essentially the `Eq` instance for the underlying hash and hence
-- is safe against timing attack (provided the underlying hashs --
-- comparison is safe under timing attack).
newtype HMAC h = HMAC h deriving (Eq, Storable, EndianStore)

-- | A function that is often used to keep type checker happy.
getHash :: HMAC h -> h
getHash _ = undefined

instance Primitive h => Primitive (HMAC h) where
  blockSize = blockSize . getHash
  -- | Stores inner and outer pad
  newtype Cxt (HMAC h) = HMACSecret B.ByteString

newtype HMACBuffer p = HMACBuffer ForeignCryptoPtr deriving Eq

data Gadget g => HMACGadget g =
  HMACGadget g (HMACBuffer (PrimitiveOf g))



instance (Primitive p, EndianStore p) => Memory (HMACBuffer p) where
  newMemory = allocMem undefined
    where
      allocMem :: (Primitive p, EndianStore p) => p -> IO (HMACBuffer p)
      allocMem p = let BYTES len = cryptoCoerce $ size p
                   in fmap HMACBuffer $ mallocForeignPtrBytes len
      size :: (Primitive p, EndianStore p) => p -> BLOCKS p
      size p = blocksOf 1 p + cryptoCoerce (BYTES $ sizeOf p)

  freeMemory (HMACBuffer fptr) = finalizeForeignPtr fptr
  withSecureMemory f bk = allocSec undefined bk >>= f
   where
     -- Assuming Blocks are always word aligned
     size :: (Primitive p, EndianStore p) => p -> BLOCKS p
     size p = blocksOf 1 p + cryptoCoerce (BYTES $ sizeOf p)
     allocSec :: (Primitive p, EndianStore p)
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
