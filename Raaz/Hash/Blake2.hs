{-|

This module exposes combinators to compute the BLAKE2b hash and the
associated HMAC for some common types.

-}

module Raaz.Hash.Blake2
       ( -- * The BLAKE2 cryptographic hashes
         BLAKE2b, BLAKE2s
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Raaz.Core

import Raaz.Hash.Internal        ( hashSource, hash, hashFile       )
import Raaz.Hash.Internal.HMAC   ( hmacSource, hmac, hmacFile, HMAC )
import Raaz.Hash.Blake2.Internal
