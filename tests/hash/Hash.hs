module Hash (tests) where

import Data.Version

import Paths_src(version)
import qualified Hash.Sha1 as Sha1
import qualified Hash.Sha224 as Sha224
import qualified Hash.Sha256 as Sha256
import qualified Hash.Sha384 as Sha384
import qualified Hash.Sha512 as Sha512
import qualified Hash.Blake256 as Blake256
import Test.Framework (defaultMain, testGroup)

tests = [ testGroup "Hash.Sha:Sha1" Sha1.tests
        , testGroup "Hash.Sha:Sha224" Sha224.tests
        , testGroup "Hash.Sha:Sha256" Sha256.tests
        , testGroup "Hash.Sha:Sha384" Sha384.tests
        , testGroup "Hash.Sha:Sha512" Sha512.tests
        , testGroup "Hash.Blake:Blake256" Blake256.tests
        ]
