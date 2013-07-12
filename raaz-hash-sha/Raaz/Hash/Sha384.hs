{-|

The Sha384 hash.

-}

module Raaz.Hash.Sha384
       ( SHA384
       , module Raaz.Primitives.Hash
       ) where

import Raaz.Primitives.Hash( sourceHash, hash, hashFile)
import Raaz.Hash.Sha512.Type(SHA384)
import Raaz.Hash.Sha512.Instance()
