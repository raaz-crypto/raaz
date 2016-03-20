{-|

This module exposes combinators to compute the SHA224 hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Sha224
       ( -- * The SHA224 cryptographic hash
         SHA224
       , sha224, sha224File, sha224Source
       -- * HMAC computation using SHA224
       , hmacSha224, hmacSha224File, hmacSha224Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Internal.HMAC   ( hmacSource, hmac, hmacFile, HMAC )
import Raaz.Hash.Sha224.Internal ( SHA224 )
import Raaz.Hash.Sha224.Recommendation()

-- | Compute the sha224 hash of an instance of `PureByteSource`. Use
-- this for computing the sha224 hash of a strict or lazy byte string.
sha224       :: PureByteSource src => src -> SHA224
sha224       = hash
{-# SPECIALIZE sha224 :: B.ByteString -> SHA224 #-}
{-# SPECIALIZE sha224 :: L.ByteString -> SHA224 #-}


-- | Compute the sha224 hash of a file.
sha224File   :: FilePath -> IO SHA224
sha224File   = hashFile

-- | Compute the sha224 hash of a general byte source.
sha224Source :: ByteSource src => src -> IO SHA224
sha224Source = hashSource

-- | Compute the message authentication code using hmac-sha224.
hmacSha224 :: PureByteSource src
           => Key (HMAC SHA224)  -- ^ Key to use
           -> src                -- ^ pure source whose hmac is to be
                                 -- computed
           -> HMAC SHA224
hmacSha224 = hmac

-- | Compute the message authentication code for a file.
hmacSha224File :: Key (HMAC SHA224) -- ^ Key to use
               -> FilePath          -- ^ File whose hmac is to be computed
               -> IO (HMAC SHA224)
hmacSha224File = hmacFile

-- | Compute the message authetication code for a generic byte source.
hmacSha224Source :: ByteSource src
                 => Key (HMAC SHA224)
                 -> src
                 -> IO (HMAC SHA224)
hmacSha224Source = hmacSource
