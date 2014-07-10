{-|

The Blake2b hash.

-}

module Raaz.Hash.Blake2b
       ( BLAKE2B, blake2b
       , blake2bFile, sourceBlake2b
       , toByteString, toHex
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Core.Types           ( toByteString               )
import Raaz.Core.Util.ByteString ( toHex                      )

import Raaz.Hash.Blake2b.Type(BLAKE2B)
import Raaz.Hash.Blake2b.Instance()

-- | Compute the blake2b hash of the given byte source.
sourceBlake2b :: ByteSource src => src -> IO BLAKE2B
sourceBlake2b = sourceHash

-- | Compute the blake2b hash of a file.
blake2bFile   :: FilePath -> IO BLAKE2B
blake2bFile   = hashFile

-- | Compute the blake2b hash of a pure byte source.
blake2b       :: PureByteSource src => src -> BLAKE2B
blake2b       = hash
{-# SPECIALIZE blake2b :: B.ByteString -> BLAKE2B #-}
{-# SPECIALIZE blake2b :: L.ByteString -> BLAKE2B #-}
