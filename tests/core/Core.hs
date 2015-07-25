module Main where

import Test.Framework (defaultMain, testGroup, Test)
import qualified Core.Types as Types
import qualified Core.Util.ByteString as ByteString
import qualified Core.C.Load as CLoad

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [ testGroup "Raaz.Types" Types.tests
        , testGroup "Raaz.Util.ByteString" ByteString.tests
        , CLoad.tests
        ]
