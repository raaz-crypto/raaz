import           Data.Version

import           Paths_src (version)
import           Test.Framework     (defaultMain, testGroup)

import qualified Modular.Number     as Number
import qualified Modular.RSA.Sign   as RSASign

pkgName = "raaz-modular-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Numbers" Number.tests
        , testGroup "RSA Signature" RSASign.tests
        ]
