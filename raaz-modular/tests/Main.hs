import Data.Version

import Paths_raaz_modular(version)
import Test.Framework (defaultMain, testGroup)

pkgName = "raaz-rsa-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [
        ]
