import Data.Version

import Paths_raaz_cipher_aes(version)
import qualified Modules.Block.Ref as BRef
import qualified Modules.ECB as ECB
import qualified Modules.CBC as CBC
import qualified Modules.CTR as CTR
import Test.Framework (defaultMain, testGroup)


pkgName = "raaz-cipher-aes-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Cipher.AES.Block" BRef.tests
        , testGroup "Raaz.Cipher.AES.ECB" ECB.tests
        , testGroup "Raaz.Cipher.AES.CBC" CBC.tests
        , testGroup "Raaz.Cipher.AES.CTR" CTR.tests
        ]
