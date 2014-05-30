{-|

The Blake256 hash.

-}

module Raaz.Hash.Blake256
       ( BLAKE256
--       , blake256, blake256File, sourceBlake256
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.ByteSource
import Raaz.Primitives.Hash( sourceHash, hash, hashFile)
import Raaz.Hash.Blake256.Type(BLAKE256)
import Raaz.Hash.Blake256.Instance()
