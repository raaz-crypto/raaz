-- |The HMAC construction for a cryptographic hash


{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE UndecidableInstances       #-}

module Raaz.Primitives.HMAC
       ( HMAC(..)
       ) where

import           Data.Bits            ( xor )
import qualified Data.ByteString      as B
import           Data.Default         ( def )
import           Data.Monoid          ( (<>)        )
import           Data.Word            ( Word8       )
import           Foreign.Storable     (Storable(..))
import           Prelude              hiding (length, replicate)
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Primitives.Hash
import           Raaz.Types
import           Raaz.Util.ByteString
import           Raaz.Util.Ptr



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

-- The padding strategy of HMAC is the same as that of the underlying
-- hash. All one needs is that the length should be 1 blocksize more
-- as we need to account for the extra block which is the inner pad.

instance (PaddableGadget g, Hash (PrimitiveOf g))
         => PaddableGadget (HMACGadget g)


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


data HMACGadget g =
  HMACGadget { hashGadget   :: g
                               -- ^ The gaget
             , outerCxtCell :: CryptoCell (Cxt (PrimitiveOf g))
                               -- ^ cell to store the outer cxt
             , hmacBuffer   :: HashMemoryBuf (PrimitiveOf g)
                               -- ^ the buffer used for hashing the
                               -- hash ( innerpad ++ message)
             }

instance (Gadget g, Hash (PrimitiveOf g), PaddableGadget g)
         => Gadget (HMACGadget g) where

  type PrimitiveOf (HMACGadget g) = HMAC (PrimitiveOf g)

  type MemoryOf (HMACGadget g) = ( MemoryOf g
                                 , CryptoCell (Cxt (PrimitiveOf g))
                                 , HashMemoryBuf (PrimitiveOf g)
                                 )

  newGadgetWithMemory (gmem, cxtCell, hbuff) = do
    g <- newGadgetWithMemory gmem
    return HMACGadget { hashGadget   = g
                      , outerCxtCell = cxtCell
                      , hmacBuffer   = hbuff
                      }

  initialize hg cxt  = do
    -- use the inner pad to initialize the
    -- hash gadget.
    initialize (hashGadget hg) $ innerCxt cxt
    -- Store the outer context in the cxtCell to use
    -- in the outer stage.
    cellStore (outerCxtCell hg) $ outerCxt cxt


  finalize hg = do
    innerHash <- fmap cxtToHash $ finalize g -- hash (inner pad ++ message)
    oc        <- cellLoad cell               -- outer context
    -- hash ( outerpad ++ inner hash)
    do initialize g oc  -- Now the first block consisting of outer pad
                        -- is hashed.
       -- Store the inner hash in the buffer and hash it.
       withMemoryBuf buf $ \ cptr -> do
             store cptr innerHash
             unsafeApplyLast g 1 (byteSize innerHash) cptr
             hcxt <- finalize g
             return $ HMACCxt hcxt hcxt
    where g    = hashGadget hg
          cell = outerCxtCell hg
          buf  = hmacBuffer hg

  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . getHash'
    where getHash' :: Gadget g => HMACGadget g -> g
          getHash' (HMACGadget g _ _) = g

  apply (HMACGadget g _ _) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks
