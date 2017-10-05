-- |The HMAC construction for a cryptographic hash


{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE ConstraintKinds            #-}
module Raaz.Hash.Internal.HMAC
       ( HMAC (..)
         -- * Combinators for computing HMACs
       , hmac, hmacFile, hmacSource
         -- ** Computing HMACs using non-standard implementations.
       , hmac', hmacFile', hmacSource'
       ) where

import           Control.Applicative
import           Control.Monad.IO.Class    (liftIO)
import           Data.Bits                 (xor)
import           Data.ByteString.Char8     (ByteString)
import qualified Data.ByteString           as B
import qualified Data.ByteString.Lazy      as L
import           Data.Monoid
import           Data.Proxy
import           Data.String
import           Data.Word
import           Foreign.Ptr               ( castPtr      )
import           Foreign.Storable          ( Storable(..) )
import           Prelude                   hiding (length, replicate)
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)

import           Raaz.Core          hiding (alignment)
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Transfer
import           Raaz.Random

import           Raaz.Hash.Internal

--------------------------- The HMAC Key -----------------------------

-- | The HMAC key type. The HMAC keys are usually of size at most the
-- block size of the associated hash, although the hmac construction
-- allows using keys arbitrary size. Using keys of small size, in
-- particular smaller than the size of the corresponding hash, can can
-- compromise security.
--
-- == A note on `Show` and `IsString` instances of keys.
--
-- As any other cryptographic type HMAC keys also have a `IsString`
-- and `Show` instance which is essentially the key expressed in
-- base16.  Keys larger than the block size of the underlying hashes
-- are shortened by applying the appropriate hash. As a result the
-- `show` and `fromString` need not be inverses of each other.
--
newtype HMACKey h = HMACKey { unKey :: B.ByteString } deriving Monoid

instance (Hash h, Recommendation h) => Storable (HMACKey h) where
  sizeOf    _  = fromEnum $ blockSize (Proxy :: Proxy h)
  alignment _  = alignment (undefined :: Word8)

  peek         = unsafeRunParser (HMACKey <$> parseByteString (blockSize (Proxy :: Proxy h))) . castPtr

  poke ptr key = unsafeWrite (writeByteString $ hmacAdjustKey key) $ castPtr ptr

hmacAdjustKey :: (Hash h, Recommendation h, Encodable h)
              => HMACKey h -- ^ the key.
              -> ByteString
hmacAdjustKey key = padIt trimedKey
  where keyStr      = unKey key
        trimedKey   = if length keyStr > sz
                      then toByteString $ keyStrHash $ theProxy key
                      else keyStr
        padIt k     = k <> replicate (sz - length k) 0
        sz          = blockSize $ theProxy key

        keyStrHash  :: (Hash h, Recommendation h) => Proxy h -> h
        keyStrHash _ = hash keyStr
        theProxy    :: HMACKey h -> Proxy h
        theProxy  _  = Proxy

-- The HMACKey is just stored as a binary data.
instance (Hash h, Recommendation h) => EndianStore (HMACKey h) where
  store            = poke
  load             = peek
  adjustEndian _ _ = return ()

instance (Hash h, Recommendation h) => RandomStorable (HMACKey h) where
  fillRandomElements = unsafeFillRandomElements

instance (Hash h, Recommendation h) => Encodable (HMACKey h)

-- | Base16 representation of the string.
instance IsString (HMACKey h) where
  fromString = HMACKey
               . (decodeFormat :: Base16 -> ByteString)
               . fromString

instance Show (HMACKey h) where
  show = show . (encodeByteString :: ByteString -> Base16) . unKey

----------------  The HMAC type -----------------------------------------

-- | The HMAC associated to a hash value. The HMAC type is essentially
-- the underlying hash type wrapped inside a newtype. Therefore, the
-- `Eq` instance for HMAC is essentially the `Eq` instance for the
-- underlying hash. It is safe against timing attack provided the
-- underlying hash comparison is safe under timing attack.
newtype HMAC h = HMAC {unHMAC :: h} deriving ( Equality
                                             , Eq
                                             , Storable
                                             , EndianStore
                                             , Encodable
                                             , IsString
                                             )
instance Show h => Show (HMAC h) where
  show  = show . unHMAC

instance Primitive h => Primitive (HMAC h) where
  type BlockSize (HMAC h) = BlockSize h
  type Implementation (HMAC h) = SomeHashI h


instance Primitive h => Symmetric (HMAC h) where
  type Key (HMAC h) = HMACKey h

-- | Compute the hash of a pure byte source like, `B.ByteString`.
hmac :: ( Hash h, Recommendation h, PureByteSource src )
     => Key (HMAC h)
     -> src  -- ^ Message
     -> HMAC h
hmac key = unsafePerformIO . hmacSource key
{-# INLINEABLE hmac #-}
{-# SPECIALIZE hmac :: (Hash h, Recommendation h) => Key (HMAC h) -> B.ByteString -> HMAC h #-}
{-# SPECIALIZE hmac :: (Hash h, Recommendation h) => Key (HMAC h) -> L.ByteString -> HMAC h #-}

-- | Compute the hmac of file.
hmacFile :: (Hash h, Recommendation h)
         => Key (HMAC h) -- ^ Key to use for mac-ing
         -> FilePath     -- ^ File to be hashed
         -> IO (HMAC h)
hmacFile key fileName = withBinaryFile fileName ReadMode $ hmacSource key
{-# INLINEABLE hmacFile #-}

-- | Compute the hmac of a generic byte source.
hmacSource :: ( Hash h, Recommendation h, ByteSource src )
           => Key (HMAC h)  -- ^ key to use for mac-ing.
           -> src           -- ^ Message
           -> IO (HMAC h)
hmacSource = go Proxy
  where go :: (Hash h, Recommendation h, ByteSource src)
              => Proxy h -> Key (HMAC h) -> src -> IO (HMAC h)
        go = hmacSource' . recommended

{-# INLINEABLE hmacSource #-}
{-# SPECIALIZE hmacSource :: (Hash h, Recommendation h) => Key (HMAC h) -> Handle -> IO (HMAC h) #-}


-- | Compute the hmac of a pure byte source like, `B.ByteString`.
hmac' :: ( Hash h, Recommendation h, PureByteSource src )
      => Implementation h
      -> Key (HMAC h)
      -> src  -- ^ Message
      -> HMAC h
hmac' impl key = unsafePerformIO . hmacSource' impl key
{-# INLINEABLE hmac' #-}
{-# SPECIALIZE hmac' :: (Hash h, Recommendation h)
                     => Implementation h
                     -> Key (HMAC h)
                     -> B.ByteString
                     -> HMAC h
  #-}
{-# SPECIALIZE hmac' :: (Hash h, Recommendation h)
                     => Implementation h
                     -> Key (HMAC h)
                     -> L.ByteString
                     -> HMAC h
  #-}


-- | Compute the hmac of file.
hmacFile' :: (Hash h, Recommendation h)
         => Implementation h
         -> Key (HMAC h)
         -> FilePath  -- ^ File to be hashed
         -> IO (HMAC h)
hmacFile' impl key fileName = withBinaryFile fileName ReadMode $ hmacSource' impl key
{-# INLINEABLE hmacFile' #-}

-- | Compute the hmac of a generic ByteSource using a given implementation.
hmacSource' :: (Hash h, Recommendation h, ByteSource src)
            => Implementation h
            -> Key (HMAC h)
            -> src
            -> IO (HMAC h)
hmacSource' imp@(SomeHashI hI) key src =
  insecurely $ do

    -- Hash the first block for the inner hash
    initialise ()
    allocate $ \ ptr -> do
      liftIO $ unsafeCopyToPointer innerFirstBlock ptr
      compress hI ptr $ toEnum 1

    -- Finish it by hashing the source.
    innerHash <- completeHashing hI src


    -- Hash the outer block.
    initialise ()
    allocate $ \ ptr -> do
      liftIO $ unsafeCopyToPointer outerFirstBlock ptr
      compress hI ptr $ toEnum 1

    -- Finish it with hashing the  hash computed above
    HMAC <$> completeHashing hI (toByteString innerHash)

  where allocate = liftPointerAction $ allocBufferFor imp $ (toEnum 1) `asTypeOf` (theBlock key)
        innerFirstBlock = B.map (xor 0x36) $ hmacAdjustKey key
        outerFirstBlock = B.map (xor 0x5c) $ hmacAdjustKey key
        theBlock :: Key (HMAC h) -> BLOCKS h
        theBlock _ = toEnum 1
