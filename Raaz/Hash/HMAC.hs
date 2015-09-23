-- |The HMAC construction for a cryptographic hash


{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE StandaloneDeriving         #-}

module Raaz.Hash.HMAC
       ( HMAC(..)
       , HMACKey
       , hmacShortenKey
       , hmac, hmac'
       ) where

import           Control.Applicative
import           Data.Bits                 (xor)
import           Data.ByteString.Char8     (ByteString)
import qualified Data.ByteString           as B
import           Data.Monoid               ((<>))
import           Data.String
import           Data.Word                 (Word8)
import           Foreign.Storable          (Storable(..))
import           Foreign.Ptr
import           Prelude                   hiding (length, replicate)
import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Symmetric
import           Raaz.Core.Primitives.Hash
import qualified Raaz.Core.Parse.Unsafe         as U
import qualified Raaz.Core.Write.Unsafe         as U
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString
import           Raaz.Core.Util.Ptr
import           Raaz.Core.Encode


-- | The HMAC associated to a hash value. The HMAC type is essentially
-- the underlying hash type wrapped inside a newtype. Therefore the
-- `Eq` instance for HMAC is essentially the `Eq` instance for the
-- underlying hash. It is safe against timing attack provided the
-- underlying hash comparison is safe under timing attack.
newtype HMAC h = HMAC h deriving (Eq, Storable, EndianStore, Show)

-- | HMAC key which is a wrapper around `ByteString` of 1 block size
-- of the underlying hash.
newtype HMACKey h = HMACKey ByteString deriving Show

-- | Base16 representation of the string.
instance Hash h => IsString (HMACKey h) where
  fromString str = key
    where getH :: Hash h1 => HMACKey h1 -> h1
          getH = undefined
          hsh  = getH key
          key  = HMACKey $ hmacShortenKey hsh $ fromString str
          key  =

instance Hash h => Storable (HMACKey h) where

  sizeOf _    = fromIntegral $ blockSize (undefined :: h)

  alignment _  = cryptoAlignment

  peek ptr    = U.runParser (castPtr ptr) $ HMACKey <$> U.parseByteString
                                                    (blockSize (undefined :: h))

  poke ptr (HMACKey bs) = U.runWrite (castPtr ptr) (U.writeByteString bs)

instance Hash h => EndianStore (HMACKey h) where
  store = poke . castPtr
  load  = peek . castPtr



instance Primitive h => Primitive (HMAC h) where

  -- | The block size is the same as the block size of the underlying
  -- hash.
  blockSize         = blockSize . getHash

  type Key (HMAC h) = HMACKey h

instance HasPadding h => HasPadding (HMAC h) where
  --
  -- The hmac algorithm is
  --
  --     hmac = hash (outer-pad + hash ( innerpad + message) )
  --
  -- The extra size of one block in hmac is to account for the
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
  | keyLen > sz = padIt $ encode $ hash key `asTypeOf` h
  | otherwise   = padIt key
  where padIt k = k <> replicate padLen 0
        sz      = blockSize h
        keyLen  = length key
        padLen  = sz - keyLen

-- | Sets the given hash gadget for doing an hmac operation. for a given key and its pad character. The
-- key is assumed of size at most the block size.
hmacSetGadget :: (Hash h, Gadget g, PrimitiveOf g ~ h)
              => Word8         -- ^ pad character
              -> HMACKey h     -- ^ key
              -> g             -- ^ Hash Gadget
              -> HashMemoryBuf h
              -> IO ()
hmacSetGadget pad k@(HMACKey key) gad buf = withMemoryBuf buf $ \ _ cptr -> do
  unsafeNCopyToCryptoPtr sz paddedKey cptr
  apply gad 1 cptr
    where sz        = blockSize (keyHash k)
          paddedKey = B.map (xor pad) key
          keyHash :: HMACKey h -> h
          keyHash = undefined

----------------------------- HMAC Gadget --------------------------------------

-- | HMAC Gadget with underlying hash gadget @g@.
data HMACGadget g =
  HMACGadget g --  The gadget to do the inner hash.
             g --  The outher hash gadget.
             (HashMemoryBuf (PrimitiveOf g))
                               -- ^ the buffer used for hashing the
                               -- hash ( innerpad ++ message)


----------------------------- Memory instance for HMACGadget ---------------------

instance (Gadget g, Hash (PrimitiveOf g)) => Memory (HMACGadget g) where

  memoryAlloc = HMACGadget <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  underlyingPtr (HMACGadget ig _ _)  = underlyingPtr ig


instance ( Gadget g
         , Hash (PrimitiveOf g)
         , IV g ~ Key (PrimitiveOf g)
         ) => InitializableMemory (HMACGadget g) where

  -- The HMAC algorithm first hashes the inner pad concatnated with
  -- the message. It then hashes the result with the outer pad
  -- prefixed. The inner and outer pads are 1 block in size hence
  -- instead of keeping the pads, we keep the context obtained after
  -- processing the first block inside the HMAC context.

  type IV (HMACGadget g) = HMACKey (PrimitiveOf g)

  initializeMemory (HMACGadget ig og  hbuf) key = do

    -- Compute inner pad
    initializeMemory ig startCxt
    hmacSetGadget 0x36 key ig hbuf

    -- Compute outer pad
    initializeMemory og startCxt
    hmacSetGadget 0x5c key og hbuf
    where
      startCxt = defaultKey $ primitiveOf ig



instance ( Gadget g
         , Hash (PrimitiveOf g)
         , FinalizableMemory g
         , FV g ~ Key (PrimitiveOf g)
         ) => FinalizableMemory (HMACGadget g) where

  type FV (HMACGadget g) = HMAC (PrimitiveOf g)

  finalizeMemory (HMACGadget _ og _) = (HMAC . hashDigest) <$> finalizeMemory og


----------------- PaddableGadget instance  -------------------------------------

-- The padding strategy of HMAC is the same as that of the underlying
-- hash. All one needs is that the length should be 1 blocksize more
-- as we need to account for the extra block which is the inner pad.

instance ( PaddableGadget g
         , Hash (PrimitiveOf g)
         , FinalizableMemory g
         , IV g ~ Key (PrimitiveOf g)
         , FV g ~ Key (PrimitiveOf g)
         )
         => PaddableGadget (HMACGadget g) where
  unsafeApplyLast (HMACGadget ig og buf) blks bytes cptr = do

    -- finish of the inner hash one for inner pad already hashed
    unsafeApplyLast ig (blks' + 1) bytes cptr

    -- Recover hash (inner pad ++ message)
    innerHash <- getDigest ig

    -- hash ( outerpad ++ inner hash)
    withMemoryBuf buf $ \ _ cptr' -> do
         store cptr' innerHash
         unsafeApplyLast og 1 (byteSize innerHash) cptr'

   where blks' = toEnum $ fromEnum blks
         getDigest :: Gadget g => g -> IO (PrimitiveOf g)
         getDigest g' = hashDigest <$> finalizeMemory g'



----------------------------- Gadget Instances ---------------------------------

-- Gadget instance for HMAC which computes the hmac of the message.
instance ( Gadget g, prim ~ PrimitiveOf g
         , Hash prim
         , IV g ~ Key prim
         , FV g ~ Key prim
         )
         => Gadget (HMACGadget g) where

  type PrimitiveOf (HMACGadget g) = HMAC (PrimitiveOf g)

  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . getHashGadget

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


--------------------------------- HMAC Auth instance ------------------------

instance Hash h => Auth (HMAC h)

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
         , FinalizableMemory g
         , Key h ~ FV g
         )
      => HMACGadget g  -- ^ HMAC Gadget type
      -> HMACKey h
      -> src           -- ^ Source
      -> HMAC h
hmac' = authTag'
{-# INLINE hmac' #-}


--}

--- | These functions are used to keep type checker happy.
getHash :: HMAC h -> h
getHash _ = undefined

getHashGadget :: HMACGadget g -> g
getHashGadget (HMACGadget g _ _) = g
