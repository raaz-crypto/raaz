import           Data.Version

import           Paths_raaz_modular (version)
import           Test.Framework     (defaultMain, testGroup)

import qualified Modules.Number     as Number
pkgName = "raaz-modular-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Numbers" Number.tests
        ]
