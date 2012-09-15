module Main where

import Test.Framework (defaultMain, testGroup)
import qualified Modules.Types as Types

main = defaultMain tests

tests = [ testGroup "Raaz.Types" Types.tests ]

