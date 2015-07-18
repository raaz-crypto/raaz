{-|

The Sha256 hash.

-}

module Raaz.Hash.Sha256
       ( SHA256, sha256
       , sha256File, sourceSha256
       -- * Encoding as binary/hexadecimal
       , toByteString, toHex
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Core.Types           ( toByteString               )
import Raaz.Core.Util.ByteString ( toHex                      )

import Raaz.Hash.Sha256.Type     ( SHA256 )
import Raaz.Hash.Sha256.Instance (        )

-- | Compute the sha256 hash of the given byte source.
sourceSha256 :: ByteSource src => src -> IO SHA256
sourceSha256 = sourceHash

-- | Compute the sha256 hash of a file.
sha256File   :: FilePath -> IO SHA256
sha256File   = hashFile

-- | Compute the sha256 hash of a pure byte source.
sha256       :: PureByteSource src => src -> SHA256
sha256       = hash
{-# SPECIALIZE sha256 :: B.ByteString -> SHA256 #-}
{-# SPECIALIZE sha256 :: L.ByteString -> SHA256 #-}
