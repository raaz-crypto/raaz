{-|

This module exposes combinators to compute the SHA1 hash and the
associated HMAC for some common types.


-}
module Raaz.Hash.Sha1
{-# DEPRECATED "SHA1 is broken. This module is here only for transition." #-}
       (
         -- * The broken SHA1 cryptographic hash.
         -- $sha1$
         SHA1
       , sha1, sha1File, sha1Source
         -- * HMAC computation using SHA1
       , hmacSha1, hmacSha1File, hmacSha1Source
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal      ( hashSource, hash, hashFile       )
import Raaz.Hash.Internal.HMAC ( hmacSource, hmac, hmacFile, HMAC )
import Raaz.Hash.Sha1.Internal ( SHA1 )
import Raaz.Hash.Sha1.Recommendation()

-- $sha1$
--
-- We already have a collision for SHA1:
-- <https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html>
--
-- While it does not yet rule out SHA1 for some specific tasks, there
-- is no reason for its continual usage. This module is present only
-- to facilitate the transition to a better hash. Use it assuming no
-- security guarantees. Raaz will not try to optimise the
-- implementations given here and will remove this module at some
-- point of time. So do not rely on this for your software.
--
--
--

{-# DEPRECATED sha1, sha1File, sha1Source
               "SHA1 is broken. This functions are here only for transition." #-}
-- | Compute the sha1 hash of an instance of `PureByteSource`. Use
-- this for computing the sha1 hash of a strict or lazy byte string.
sha1       :: PureByteSource src => src -> SHA1
sha1       = hash


{-# SPECIALIZE sha1 :: B.ByteString -> SHA1 #-}
{-# SPECIALIZE sha1 :: L.ByteString -> SHA1 #-}


-- | Compute the sha1 hash of a file.
sha1File   :: FilePath -> IO SHA1
sha1File   = hashFile

-- | Compute the sha1 hash of a general byte source.
sha1Source :: ByteSource src => src -> IO SHA1
sha1Source = hashSource


{-# DEPRECATED hmacSha1, hmacSha1File, hmacSha1Source
               "SHA1 is broken. This functions are here only for transition." #-}

-- | Compute the message authentication code using hmac-sha1.
hmacSha1 :: PureByteSource src  => Key (HMAC SHA1) -> src -> HMAC SHA1
hmacSha1 = hmac

-- | Compute the message authentication code for a file.
hmacSha1File :: Key (HMAC SHA1) -> FilePath -> IO (HMAC SHA1)
hmacSha1File = hmacFile

-- | Compute the message authetication code for a generic byte source.
hmacSha1Source :: ByteSource src => Key (HMAC SHA1) -> src -> IO (HMAC SHA1)
hmacSha1Source = hmacSource
