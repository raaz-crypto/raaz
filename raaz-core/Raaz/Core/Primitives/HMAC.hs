-- |The HMAC construction for a cryptographic hash


{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE UndecidableInstances       #-}

module Raaz.Core.Primitives.HMAC
       ( HMAC(..)
       , HMACKey
       , hmacShortenKey
       , hmac, hmac'
       ) where

import           Control.Applicative
import           Data.Bits                 (xor)
import           Data.ByteString.Char8     (ByteString)
import qualified Data.ByteString           as B
import           Data.Default              (def)
import           Data.Monoid               ((<>))
import           Data.String
import           Data.Word                 (Word8)
import           Foreign.Storable          (Storable(..))
import           Foreign.Ptr
import           Prelude                   hiding (length, replicate)
import           System.IO.Unsafe          (unsafePerformIO)

import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Symmetric
import           Raaz.Core.Primitives.Hash
import           Raaz.Core.Parse
import qualified Raaz.Core.Parse.Unsafe         as U
import           Raaz.Core.Write
import qualified Raaz.Core.Write.Unsafe         as U
import           Raaz.Core.Serialize
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString
import           Raaz.Core.Util.Ptr



-- | The HMAC associated to a hash value. The HMAC type is essentially
-- the underlying hash type wrapped inside a newtype. Therefore the
-- `Eq` instance for HMAC is essentially the `Eq` instance for the
-- underlying hash. It is safe against timing attack provided the
-- underlying hash comparison is safe under timing attack.
newtype HMAC h = HMAC h deriving (Eq, Storable, EndianStore, Show)

-- | HMAC key which is a wrapper around `ByteString` of 1 block size
-- of the underlying hash.
newtype HMACKey h = HMACKey ByteString deriving Show

instance Hash h => IsString (HMACKey h) where
  fromString str = key
    where getH :: Hash h1 => HMACKey h1 -> h1
          getH = undefined
          hsh  = getH key
          key  = HMACKey $ hmacShortenKey hsh $ fromString str

-- | `HMACKey` can be built from any source of 1 block size.
instance Hash h => CryptoSerialize (HMACKey h) where

  -- | The parser reads exactly 1 block of data from the buffer. Thus
  -- user should take care that the key is exactly 1 block size. The
  -- usual trick is to hash keys (see `hmacShortenKey`) which are
  -- larger.
  cryptoParse = HMACKey <$> parseByteString (blockSize (undefined :: h))

  -- | Writer just writes the underlying bytestring to the buffer.
  cryptoWrite (HMACKey bs) = writeByteString bs


instance Hash h => Storable (HMACKey h) where

  sizeOf _    = fromIntegral $ blockSize (undefined :: h)

  alignment _ = cryptoAlignment

  peek ptr    = U.runParser (castPtr ptr) $ HMACKey <$> U.parseByteString
                                                    (blockSize (undefined :: h))

  poke ptr (HMACKey bs) = U.runWrite (castPtr ptr) (U.writeByteString bs)


instance Primitive h => Primitive (HMAC h) where

  -- | The block size is the same as the block size of the underlying
  -- hash.
  blockSize         = blockSize . getHash

  -- The HMAC algorithm first hashes the inner pad concatnated with
  -- the message. It then hashes the result with the outer pad
  -- prefixed. The inner and outer pads are 1 block in size hence
  -- instead of keeping the pads, we keep the context obtained after
  -- processing the first block inside the HMAC context.
  data Cxt (HMAC h) = HMACCxt { innerCxt :: (Cxt h)
                              , outerCxt  :: (Cxt h)
                              }

instance HasPadding h => HasPadding (HMAC h) where
  --
  -- The hmac algorithm is
  --
  --     hmac = hash (outer-pad + hash ( innerpad + message) )
  --
  -- The extra size of one block in hmac is to account for the the
  -- inner pad that is already hashed before the actual data is
  -- processed.

  padLength hmc bits = padLength h bits'
    where h     = getHash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  padding hmc bits = padding h bits'
    where h     = getHash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  unsafePad hmc bits = unsafePad h bits'
    where h     = getHash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  maxAdditionalBlocks  = toEnum . fromEnum
                       . maxAdditionalBlocks
                       . getHash

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
        => Word8         -- ^ pad character
        -> HMACKey h     -- ^ key
        -> Cxt h
hmacCxt pad k@(HMACKey key) = unsafePerformIO $ withGadget def $ go (keyHash k)
  where
    keyHash :: HMACKey h -> h
    keyHash = undefined
    go :: Hash hsh => hsh -> Recommended hsh -> IO (Cxt hsh)
    go hsh gad = allocaBuffer sz $ \ buf  -> do
      unsafeNCopyToCryptoPtr sz paddedKey buf
      apply gad 1 buf
      finalize gad
        where sz        = blockSize hsh
              paddedKey = hmacPad sz pad key

----------------------------- HMAC Gadget --------------------------------------

-- | HMAC Gadget with underlying hash gadget @g@.
data HMACGadget g =
  HMACGadget { hashGadget   :: g
                               -- ^ The gaget
             , outerCxtCell :: CryptoCell (Cxt (PrimitiveOf g))
                               -- ^ cell to store the outer cxt
             , hmacBuffer   :: HashMemoryBuf (PrimitiveOf g)
                               -- ^ the buffer used for hashing the
                               -- hash ( innerpad ++ message)
             }

----------------- PaddableGadget instance  -------------------------------------

-- The padding strategy of HMAC is the same as that of the underlying
-- hash. All one needs is that the length should be 1 blocksize more
-- as we need to account for the extra block which is the inner pad.

instance (PaddableGadget g, Hash (PrimitiveOf g))
         => PaddableGadget (HMACGadget g) where
  unsafeApplyLast (HMACGadget g _ _) blks = unsafeApplyLast g (blks' + 1) -- one for inner pad already hashed
    where blks' = toEnum $ fromEnum blks

----------------------------- Gadget Instances ---------------------------------

-- Gadget instance for HMAC which computes the hmac of the message.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         ) => Gadget (HMACGadget g) where

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
    innerHash <- fmap toDigest $ finalize g  -- hash (inner pad ++ message)
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

  apply (HMACGadget g _ _) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks


-- | CryptoPrimitive instance which uses the CryptoPrimitive instance
-- of the underlying hash.
instance ( Hash h
         , CryptoPrimitive h
         , PrimitiveOf (HMACGadget (Recommended h)) ~ HMAC h
         , PrimitiveOf (HMACGadget (Reference h)) ~ HMAC h
         ) => CryptoPrimitive (HMAC h) where
  type Recommended (HMAC h) = HMACGadget (Recommended h)
  type Reference   (HMAC h) = HMACGadget (Reference h)

-------------------------------- Digestible instances -----------------------

instance Hash h => Digestible (HMAC h) where
  type Digest (HMAC h)      = HMAC h

  toDigest (HMACCxt icxt _) = HMAC $ toDigest icxt


--------------------------------- HMAC Auth instance ------------------------

-- Both Auth and Verify Mode keys are same for HMAC.
type instance Key (HMAC h) = HMACKey h

instance Hash h => Auth (HMAC h) where
  -- | The Auth context can be built out of the starting string. The
  -- inner and outer pads are strings of one block size. We store the
  -- context obtaining from hashing these strings.
  authCxt key = HMACCxt iCxt oCxt
    where
      iCxt = hmacCxt 0x36 key
      oCxt = hmacCxt 0x5c key


-- | Compute the HMAC of pure byte source.
hmac :: (Hash h, PureByteSource src)
     => HMACKey h
     -> src          -- ^ Source
     -> HMAC h
hmac = authTag
{-# INLINE hmac #-}

-- | Compute the HMAC of pure byte source using the given gadget. Note
-- that the gadget supplied is just used to know the type of gadget
-- used. You can even supply an `undefined` with the intended type of
-- gadget.
hmac' :: ( Hash h
         , PureByteSource src
         , PaddableGadget g
         , PrimitiveOf g ~ h
         )
      => HMACGadget g  -- ^ HMAC Gadget type
      -> HMACKey h
      -> src           -- ^ Source
      -> HMAC h
hmac' = authTag'
{-# INLINE hmac' #-}

--- | These functions are used to keep type checker happy.
getHash :: HMAC h -> h
getHash _ = undefined

getHash' :: HMACGadget g -> g
getHash' (HMACGadget g _ _) = g
