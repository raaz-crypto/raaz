module Main where

import Test.Framework (defaultMain, testGroup)
import qualified Modules.Types as Types
import qualified Modules.Util.ByteString as ByteString

main = defaultMain tests

tests = [ testGroup "Raaz.Types" Types.tests
        , testGroup "Raaz.Util.ByteString" ByteString.tests
        ]

