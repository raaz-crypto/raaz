module Curves (tests) where

import           Data.Version

import           Paths_src (version)
import qualified Curves.EC25519.Defaults as EC25519
import           Test.Framework     (defaultMain, testGroup)

tests = [ testGroup "EC25519" EC25519.tests ]
