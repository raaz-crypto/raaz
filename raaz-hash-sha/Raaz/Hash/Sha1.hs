{-|

The Sha1 hash.

-}

module Raaz.Hash.Sha1
       ( SHA1
       , module Raaz.Primitives.Hash
       ) where

import Raaz.Primitives.Hash( sourceHash, hash, hashFile)
import Raaz.Hash.Sha1.Type(SHA1)
import Raaz.Hash.Sha1.Instance()
