module Cipher (tests) where

import Data.Version

import Paths_src(version)
import qualified Cipher.AES as AES
import qualified Cipher.Salsa20 as Salsa20
import Test.Framework (defaultMain, testGroup)

tests = [ testGroup "AES" AES.tests
        , testGroup "Salsa20" Salsa20.tests
        ]
