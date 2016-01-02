{-|

The Sha384 hash.

-}

module Raaz.Hash.Sha384
       ( SHA384, sha384
       , sha384File, sourceSha384
       -- * Encoding as binary/hexadecimal
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )

import Raaz.Hash.Sha384.Type     ( SHA384 )
import Raaz.Hash.Sha384.Instance (        )

-- | Compute the sha384 hash of the given byte source.
sourceSha384 :: ByteSource src => src -> IO SHA384
sourceSha384 = sourceHash

-- | Compute the sha384 hash of a file.
sha384File   :: FilePath -> IO SHA384
sha384File   = hashFile

-- | Compute the sha384 hash of a pure byte source.
sha384       :: PureByteSource src => src -> SHA384
sha384       = hash
{-# SPECIALIZE sha384 :: B.ByteString -> SHA384 #-}
{-# SPECIALIZE sha384 :: L.ByteString -> SHA384 #-}
