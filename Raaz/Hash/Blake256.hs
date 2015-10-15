{-|

The Blake256 hash.

-}

module Raaz.Hash.Blake256
       ( BLAKE256, blake256
       , blake256File, sourceBlake256
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Hash.Blake256.Type(BLAKE256)
import Raaz.Hash.Blake256.Instance()

-- | Compute the blake256 hash of the given byte source.
sourceBlake256 :: ByteSource src => src -> IO BLAKE256
sourceBlake256 = sourceHash

-- | Compute the blake256 hash of a file.
blake256File   :: FilePath -> IO BLAKE256
blake256File   = hashFile

-- | Compute the blake256 hash of a pure byte source.
blake256       :: PureByteSource src => src -> BLAKE256
blake256       = hash
{-# SPECIALIZE blake256 :: B.ByteString -> BLAKE256 #-}
{-# SPECIALIZE blake256 :: L.ByteString -> BLAKE256 #-}
