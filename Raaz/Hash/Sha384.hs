{-|

This module exposes combinators to compute the SHA384 hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Sha384
       ( -- * The SHA384 cryptographic hash
         SHA384
       , sha384, sha384File, sha384Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Sha384.Internal ( SHA384 )
import Raaz.Hash.Sha384.Recommendation()

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
