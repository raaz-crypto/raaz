{-|

This module exposes combinators to compute the SHA384 hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Sha384
       ( -- * The SHA384 cryptographic hash
         SHA384
       , sha384, sha384File, sha384Source
       -- * HMAC computation using SHA384
       , hmacSha384, hmacSha384File, hmacSha384Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Internal.HMAC   ( hmacSource, hmac, hmacFile, HMAC )
import Raaz.Hash.Sha384.Internal ( SHA384 )


-- | Compute the sha384 hash of an instance of `PureByteSource`. Use
-- this for computing the sha384 hash of a strict or lazy byte string.
sha384       :: PureByteSource src => src -> SHA384
sha384       = hash
{-# SPECIALIZE sha384 :: B.ByteString -> SHA384 #-}
{-# SPECIALIZE sha384 :: L.ByteString -> SHA384 #-}


-- | Compute the sha384 hash of a file.
sha384File   :: FilePath -> IO SHA384
sha384File   = hashFile

-- | Compute the sha384 hash of a general byte source.
sha384Source :: ByteSource src => src -> IO SHA384
sha384Source = hashSource

-- | Compute the message authentication code using hmac-sha384.
hmacSha384 :: PureByteSource src
           => Key (HMAC SHA384)  -- ^ Key to use
           -> src                -- ^ pure source whose hmac is to be
                                 -- computed
           -> HMAC SHA384
hmacSha384 = hmac

-- | Compute the message authentication code for a file.
hmacSha384File :: Key (HMAC SHA384) -- ^ Key to use
               -> FilePath          -- ^ File whose hmac is to be computed
               -> IO (HMAC SHA384)
hmacSha384File = hmacFile

-- | Compute the message authetication code for a generic byte source.
hmacSha384Source :: ByteSource src
                 => Key (HMAC SHA384)
                 -> src
                 -> IO (HMAC SHA384)
hmacSha384Source = hmacSource
