module Modules.AES (tests) where

-- import qualified Modules.AES.Block as B
-- import qualified Modules.AES.ECB as ECB
import qualified Modules.AES.CBC as CBC
import qualified Modules.AES.CTR as CTR

import Test.Framework

tests = [ -- testGroup "Raaz.Cipher.AES.Block" B.tests
          testGroup "Raaz.Cipher.AES.CBC" CBC.tests
        , testGroup "Raaz.Cipher.AES.CTR" CTR.tests
        -- testGroup "Raaz.Cipher.AES.ECB" ECB.tests
        ]
