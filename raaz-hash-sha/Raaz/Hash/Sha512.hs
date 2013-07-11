{-|

The Sha512 hash.

-}

module Raaz.Hash.Sha512
       ( SHA512
       , module Raaz.Primitives.Hash
       ) where

import Raaz.Primitives.Hash( sourceHash, hash, hashFile)
import Raaz.Hash.Sha512.Type(SHA512)
import Raaz.Hash.Sha512.Instance()
