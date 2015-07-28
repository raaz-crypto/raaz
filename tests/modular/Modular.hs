module Modular (tests) where

import           Data.Version

import           Paths_src (version)
import           Test.Framework     (defaultMain, testGroup)

import qualified Modular.Number     as Number
import qualified Modular.RSA.Sign   as RSASign

tests = [ testGroup "Numbers" Number.tests
        , testGroup "RSA Signature" RSASign.tests
        ]
