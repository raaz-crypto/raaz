import           Data.Version

import           Paths_raaz_modular (version)
import           Test.Framework     (defaultMain, testGroup)

import qualified Modules.Number     as Number
import qualified Modules.RSA.Sign   as RSASign

pkgName = "raaz-modular-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Numbers" Number.tests
        , testGroup "RSA Signature" RSASign.tests
        ]
