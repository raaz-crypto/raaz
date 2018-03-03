{-|

This module exposes combinators to compute the SHA512 hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Sha512
       ( -- * The SHA512 cryptographic hash
         SHA512
       , sha512, sha512File, sha512Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Sha512.Internal ( SHA512 )
import Raaz.Hash.Sha512.Recommendation()

-- | Compute the sha512 hash of an instance of `PureByteSource`. Use
-- this for computing the sha512 hash of a strict or lazy byte string.
sha512       :: PureByteSource src => src -> SHA512
sha512       = hash
{-# SPECIALIZE sha512 :: B.ByteString -> SHA512 #-}
{-# SPECIALIZE sha512 :: L.ByteString -> SHA512 #-}


-- | Compute the sha512 hash of a file.
sha512File   :: FilePath -> IO SHA512
sha512File   = hashFile

-- | Compute the sha512 hash of a general byte source.
sha512Source :: ByteSource src => src -> IO SHA512
sha512Source = hashSource
