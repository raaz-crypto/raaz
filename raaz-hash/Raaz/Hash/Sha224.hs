{-|

The Sha224 hash.

-}

module Raaz.Hash.Sha224
       ( SHA224, sha224
       , sha224File, sourceSha224
       -- * Encoding as binary/hexadecimal
       , toByteString, toHex
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.ByteSource
import Raaz.Primitives.Hash( sourceHash, hash, hashFile)
import Raaz.Hash.Sha224.Type(SHA224)
import Raaz.Hash.Sha224.Instance()
import Raaz.Types           ( toByteString               )
import Raaz.Util.ByteString ( toHex                      )

-- | Compute the sha224 hash of the given byte source.
sourceSha224 :: ByteSource src => src -> IO SHA224
sourceSha224 = sourceHash

-- | Compute the sha224 hash of a file.
sha224File   :: FilePath -> IO SHA224
sha224File   = hashFile

-- | Compute the sha224 hash of a pure byte source.
sha224       :: PureByteSource src => src -> SHA224
sha224       = hash
{-# SPECIALIZE sha224 :: B.ByteString -> SHA224 #-}
{-# SPECIALIZE sha224 :: L.ByteString -> SHA224 #-}
