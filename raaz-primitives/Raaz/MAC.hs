{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.MAC
       ( MAC(..)
       , HMAC(..)
       ) where
import Control.Applicative
import Data.ByteString(ByteString)
import Foreign.Storable

import Raaz.Types
import Raaz.Primitives

-- | The class that captures a cryptographic message authentication
-- algorithm. The associated type @MAC m@ captures the actual MAC
-- value.
--
-- [Warning] While defining the @'Eq'@ instance of @'MAC' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
--

class ( BlockPrimitive m
      , HasPadding  m
      , Eq          m
      , CryptoStore m
      ) => MAC m where

  -- | The secret key
  data MACSecret m :: *

  -- | Convert a bytestring to a secret
  toMACSecret  :: m -> ByteString -> MACSecret m

  -- | The starting MAC context
  startMACCxt  :: MACSecret m -> Cxt m

  -- | Finalise the context to a MAC value.
  finaliseMAC  :: MACSecret m -> Cxt m -> m


-- | The HMAC associated to a hash value. The `Eq` instance for HMAC
-- is essentially the `Eq` instance for the underlying hash and hence
-- is safe against timing attack (provided the underlying hashs
-- comparison is safe under timing attack).
newtype HMAC h = HMAC h deriving (Eq, Storable, CryptoStore)

getHash :: HMAC h -> h
getHash _ = undefined

instance BlockPrimitive h => BlockPrimitive (HMAC h) where

  blockSize         = blockSize . getHash
  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . getHash

  newtype Cxt (HMAC h) = HMACCxt (Cxt h)

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
