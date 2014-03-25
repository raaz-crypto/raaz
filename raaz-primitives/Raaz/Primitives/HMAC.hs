-- |The HMAC construction for a cryptographic hash


{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
module Raaz.Primitives.HMAC
       ( HMAC(..)
       ) where

import           Data.Bits            ( xor )
import qualified Data.ByteString      as B
import           Data.Default         ( def )
import           Data.Monoid          ( (<>)        )
import           Data.Word            ( Word8       )
import           Foreign.Storable     (Storable(..))
import           Foreign.ForeignPtr.Safe
import           Prelude              hiding (length, replicate)
import           System.IO            (withBinaryFile, IOMode(ReadMode), Handle)
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.ByteSource
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Types
import           Raaz.Util.ByteString
import           Raaz.Util.Ptr
import           Raaz.Util.SecureMemory

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Hash


-- | The HMAC associated to a hash value. The HMAC type is essentially
-- the underlying hash type wrapped inside a newtype. Therefore the
-- `Eq` instance for HMAC is essentially the `Eq` instance for the
-- underlying hash. It is safe against timing attack provided the
-- underlying hash comparison is safe under timing attack.
newtype HMAC h = HMAC h deriving (Eq, Storable, EndianStore)

-- | A function that is often used to keep type checker happy.
getHash :: HMAC h -> h
getHash _ = undefined


instance Primitive h => Primitive (HMAC h) where

  -- | The block size is the same as the block size of the underlying
  -- hash.
  blockSize         = blockSize . getHash

  -- The HMAC algorithm first hashes the inner pad concatnated with
  -- the message. It then hashes the result with the outer pad
  -- prefixed. The inner and outer pads are 1 block in size hence
  -- instead of keeping the pads, we keep the context obtained after
  -- processing the first block inside the HMAC context.
  data Cxt (HMAC h) = HMACCxt { innerCxt :: Cxt h
                              , outerCxt :: Cxt h
                              }

instance SafePrimitive h => SafePrimitive (HMAC h)

-------------------- HMAC context from the key -----------------------

instance Hash h => Initializable (HMAC h) where
  cxtSize   = error "hmac cxtSize is unbounded"

  -- The HMAC context can be built out of the starting string. The
  -- inner and outer pads are strings of one block size. We store the
  -- context obtaining from hashing these strings.
  getCxt bs = cxt
    where cxt = HMACCxt { innerCxt = hmacCxt thisHash 0x36 key
                        , outerCxt = hmacCxt thisHash 0x5c key
                        }
          key       = hmacShortenKey thisHash bs
          thisHmac  = getPrim cxt
          thisHash  = getHash thisHmac
          --
          -- Helper function to make type checker happy
          --
          getPrim :: (Primitive prim) => Cxt prim -> prim
          getPrim _ = undefined


-- | Shorten a key that is longer than the block size.
hmacShortenKey :: Hash h
               => h            -- ^ underlying hash
               -> B.ByteString -- ^ the key.
               -> B.ByteString
hmacShortenKey h key
  | length key > blockSize h = toByteString (hash key `asTypeOf` h)
  | otherwise                = key

-- | This function computes the padded key for for a given byteString.
-- We will assume that the key is of size at most the block size.
hmacPad :: BYTES Int    -- ^ Block size
        -> Word8        -- ^ The pad character
        -> B.ByteString -- ^ the pad size
        -> B.ByteString
hmacPad sz pad key =  B.map (xor pad) key
                              <> replicate extra pad
  where extra = sz - length key

-- | Compute the hmac cxt for a given key and its pad character. The
-- key is assumed of size at most the block size.
hmacCxt :: Hash h
       => h             -- ^ underlying hash
       -> Word8         -- ^ pad character
       -> B.ByteString  -- ^ key
       -> Cxt h
hmacCxt h pad key  = unsafePerformIO $ withGadget def $ go h
  where go :: Hash hsh => hsh -> Recommended hsh -> IO (Cxt hsh)
        go hsh gad = allocaBuffer sz $ \ buf  -> do
          unsafeNCopyToCryptoPtr sz paddedKey buf
          apply gad 1 buf
          finalize gad
          where sz        = blockSize hsh
                paddedKey = hmacPad sz pad key

----------------- Padding strategy of HMAC ------------------------

instance HasPadding h => HasPadding (HMAC h) where
  --
  -- The hmac algorithm is
  --
  --     hmac = hash (outer-pad + hash ( innerpad + message) )
  --
  -- The extra size of one block in hmac is to account for the the
  -- inner pad that is already hashed before the actual data is
  -- processed.

  padLength hmac bits = padLength h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  padding hmac bits = padding h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  unsafePad hmac bits = unsafePad h bits'
    where h     = getHash hmac
          bits' = bits + cryptoCoerce (blocksOf 1 hmac)

  maxAdditionalBlocks  = toEnum . fromEnum
                       . maxAdditionalBlocks
                       . getHash

{--

instance Gadget g => Gadget (HMAC g) where

  type PrimitiveOf (HMAC g) = HMAC (PrimitiveOf g)

  type MemoryOf (HMAC g) = (MemoryOf g, HMACBuffer (PrimitiveOf g))

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
--}
