{-|

This module exposes combinators to compute the SHA256 hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Sha256
       ( -- * The SHA256 cryptographic hash
         SHA256
       , sha256, sha256File, sha256Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Sha256.Internal ( SHA256 )
import Raaz.Hash.Sha256.Recommendation()

-- | Compute the sha256 hash of an instance of `PureByteSource`. Use
-- this for computing the sha256 hash of a strict or lazy byte string.
sha256       :: PureByteSource src => src -> SHA256
sha256       = hash
{-# SPECIALIZE sha256 :: B.ByteString -> SHA256 #-}
{-# SPECIALIZE sha256 :: L.ByteString -> SHA256 #-}


-- | Compute the sha256 hash of a file.
sha256File   :: FilePath -> IO SHA256
sha256File   = hashFile

-- | Compute the sha256 hash of a general byte source.
sha256Source :: ByteSource src => src -> IO SHA256
sha256Source = hashSource
