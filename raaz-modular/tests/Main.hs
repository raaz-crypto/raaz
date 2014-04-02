import Data.Version

import Paths_raaz_modular(version)
import Test.Framework (defaultMain, testGroup)

import qualified Modules.RSA.Primitives as P
import qualified Modules.RSA.Cipher as C
import qualified Modules.RSA.Sign as S

pkgName = "raaz-rsa-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.RSA.Primitives" P.tests
        , testGroup "RSA Encryption/Decryption" C.tests
        , testGroup "RSA Signature" S.tests
        ]
