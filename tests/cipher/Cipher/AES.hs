module Cipher.AES (tests) where

-- import qualified Cipher.AES.Block as B
-- import qualified Cipher.AES.ECB as ECB
import qualified Cipher.AES.CBC as CBC
import qualified Cipher.AES.CTR as CTR

import Test.Framework

tests = [ -- testGroup "Raaz.Cipher.AES.Block" B.tests
          testGroup "Raaz.Cipher.AES.CBC" CBC.tests
        , testGroup "Raaz.Cipher.AES.CTR" CTR.tests
        -- testGroup "Raaz.Cipher.AES.ECB" ECB.tests
        ]
