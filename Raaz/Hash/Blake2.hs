{-|

This module exposes combinators to compute the BLAKE2b hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Blake2
       ( -- * The BLAKE2 cryptographic hashes
         BLAKE2b, BLAKE2s
       , blake2b, blake2bFile, blake2bSource
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Blake2.Internal
import Raaz.Hash.Blake2.Recommendation()

-- | Compute the blake2b hash of an instance of `PureByteSource`. Use
-- this for computing the sha1 hash of a strict or lazy byte string.
blake2b       :: PureByteSource src => src -> BLAKE2b
blake2b       = hash


{-# SPECIALIZE blake2b :: B.ByteString -> BLAKE2b #-}
{-# SPECIALIZE blake2b :: L.ByteString -> BLAKE2b #-}


-- | Compute the blake2b hash of a file.
blake2bFile   :: FilePath -> IO BLAKE2b
blake2bFile   = hashFile

-- | Compute the blake2b hash of a general byte source.
blake2bSource :: ByteSource src => src -> IO BLAKE2b
blake2bSource = hashSource
