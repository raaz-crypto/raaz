import Data.Version

import Paths_raaz_cipher(version)
import qualified Modules.AES as AES
import qualified Modules.Salsa20 as Salsa20
import Test.Framework (defaultMain, testGroup)



pkgName = "raaz-cipher-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "AES" AES.tests
        , testGroup "Salsa20" Salsa20.tests
        ]
