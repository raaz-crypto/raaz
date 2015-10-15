{-|

The Sha1 hash.

-}

module Raaz.Hash.Sha1
       ( SHA1, sha1
       , sha1File, sourceSha1
       -- * Encoding as binary/hexadecimal
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )

import Raaz.Hash.Sha1.Type     ( SHA1 )
import Raaz.Hash.Sha1.Instance (      )

-- | Compute the sha1 hash of the given byte source.
sourceSha1 :: ByteSource src => src -> IO SHA1
sourceSha1 = sourceHash

-- | Compute the sha1 hash of a file.
sha1File   :: FilePath -> IO SHA1
sha1File   = hashFile

-- | Compute the sha1 hash of a pure byte source.
sha1       :: PureByteSource src => src -> SHA1
sha1       = hash
{-# SPECIALIZE sha1 :: B.ByteString -> SHA1 #-}
{-# SPECIALIZE sha1 :: L.ByteString -> SHA1 #-}
