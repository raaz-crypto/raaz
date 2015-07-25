module Cipher.Salsa20 (tests) where

import qualified Cipher.Salsa20.Block as B
import qualified Cipher.Salsa20.Stream as S

import Test.Framework

tests = [ testGroup "Raaz.Cipher.Salsa20.Block" B.tests
        , testGroup "Raaz.Cipher.Salsa20" S.tests
        ]
