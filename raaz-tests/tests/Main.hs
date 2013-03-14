module Main where

import Test.Framework (defaultMain, testGroup, Test)
import qualified Modules.Types as Types
import qualified Modules.Util.ByteString as ByteString
import qualified Modules.C.Portable.Load as CPLoad

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [ testGroup "Raaz.Types" Types.tests
        , testGroup "Raaz.Util.ByteString" ByteString.tests
        , testGroup "Portable C load" CPLoad.tests
        ]
