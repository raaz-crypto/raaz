module Modules.Sha1
       ( tests
       ) where


import Test.Framework


import Raaz.Test.CryptoStore
import Raaz.Test.Hash
import Raaz.Primitives.Hash.Sha


tests = allHashTests (undefined ::SHA1)
