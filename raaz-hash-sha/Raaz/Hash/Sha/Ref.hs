{-|

This module provides the reference implementation of the SHA family of
hash functions. Depending on your platform there might be a more
efficient implementation. So you /should not/ be using this code in
production.

-}

module Raaz.Hash.Sha.Ref
       ( module Raaz.Hash.Sha.Ref.Sha1
       ) where

import Raaz.Hash.Sha.Ref.Sha1
