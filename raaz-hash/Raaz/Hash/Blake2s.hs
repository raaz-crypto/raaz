{-|

The Blake2s hash.

-}

module Raaz.Hash.Blake2s
       ( BLAKE2S, blake2s
       , blake2sFile, sourceBlake2s
       , toByteString, toHex
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core.ByteSource
import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Core.Types           ( toByteString               )
import Raaz.Core.Util.ByteString ( toHex                      )

import Raaz.Hash.Blake2s.Type(BLAKE2S)
import Raaz.Hash.Blake2s.Instance()

-- | Compute the blake2s hash of the given byte source.
sourceBlake2s :: ByteSource src => src -> IO BLAKE2S
sourceBlake2s = sourceHash

-- | Compute the blake2s hash of a file.
blake2sFile   :: FilePath -> IO BLAKE2S
blake2sFile   = hashFile

-- | Compute the blake2s hash of a pure byte source.
blake2s       :: PureByteSource src => src -> BLAKE2S
blake2s      = hash
{-# SPECIALIZE blake2s :: B.ByteString -> BLAKE2S #-}
{-# SPECIALIZE blake2s :: L.ByteString -> BLAKE2S #-}
