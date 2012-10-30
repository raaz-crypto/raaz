module Modules.Sha1
       ( tests
       ) where


import Test.Framework


import Raaz.Test.CryptoStore
import Raaz.Test.Hash
import Raaz.Hash.Sha


tests = [ testStoreLoad (undefined :: SHA1)
        , testPadLengthVsPadding (undefined :: SHA1)
        , testLengthDivisibility (undefined :: SHA1)
        ]

